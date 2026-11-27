package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/auth"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/cloud_client"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/policy"
)

type ActionRequest struct {
	CorrelationID   string                   `json:"correlation_id"`
	Principal       string                   `json:"principal"`
	Role            string                   `json:"role"`
	Action          string                   `json:"action"`
	RoleName        string                   `json:"role_name"`
	PolicyARN       string                   `json:"policy_arn"`
	RoleARN         string                   `json:"role_arn"`
	SessionName     string                   `json:"session_name"`
	DurationSeconds int32                    `json:"duration_seconds"`
	BreakGlass      policy.BreakGlassRequest `json:"break_glass"`
}

type ActionResponse struct {
	CorrelationID string                        `json:"correlation_id"`
	Status        string                        `json:"status"`
	PolicyReason  string                        `json:"policy_reason"`
	Credentials   *cloud_client.AssumeRoleResult `json:"credentials,omitempty"`
}

type HealthProbe func(ctx context.Context) (localstackOK bool, opaOK bool)

type Gateway struct {
	verifier    *auth.Verifier
	evaluator   *policy.Evaluator
	awsClient   *cloud_client.AWSManagementClient
	healthProbe HealthProbe
	logger      *slog.Logger
	nowUTC      func() time.Time
}

func NewGateway(
	verifier *auth.Verifier,
	evaluator *policy.Evaluator,
	awsClient *cloud_client.AWSManagementClient,
	healthProbe HealthProbe,
	logger *slog.Logger,
) *Gateway {
	if logger == nil {
		logger = slog.Default()
	}
	return &Gateway{
		verifier:    verifier,
		evaluator:   evaluator,
		awsClient:   awsClient,
		healthProbe: healthProbe,
		logger:      logger,
		nowUTC:      func() time.Time { return time.Now().UTC() },
	}
}

func (g *Gateway) SetNowUTC(fn func() time.Time) {
	g.nowUTC = fn
}

func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", g.handleHealthz)
	mux.HandleFunc("POST /v1/actions", g.handleAction)
	return mux
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, r *http.Request) {
	lsOK, opaOK := true, true
	if g.healthProbe != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		lsOK, opaOK = g.healthProbe(ctx)
	}
	code := http.StatusOK
	status := "healthy"
	if !lsOK || !opaOK {
		code = http.StatusServiceUnavailable
		status = "degraded"
	}
	writeJSON(w, code, map[string]any{
		"status":     status,
		"localstack": lsOK,
		"opa":        opaOK,
		"timestamp":  g.nowUTC().Format(time.RFC3339),
	})
}

func (g *Gateway) handleAction(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
		return
	}

	sig := r.Header.Get("X-Signature-256")
	ts := r.Header.Get("X-Timestamp")
	if err := g.verifier.Verify(sig, ts, body); err != nil {
		g.logger.Warn("rejected unauthenticated request", "error", err.Error())
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	var req ActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if req.CorrelationID == "" {
		req.CorrelationID = r.Header.Get("X-Correlation-ID")
	}
	if req.CorrelationID == "" {
		req.CorrelationID = fmt.Sprintf("corr-%d", g.nowUTC().UnixNano())
	}

	targetARN := req.PolicyARN
	if targetARN == "" {
		targetARN = req.RoleARN
	}

	decision, err := g.evaluator.Evaluate(r.Context(), policy.EvaluationInput{
		CorrelationID: req.CorrelationID,
		Principal:     req.Principal,
		Role:          req.Role,
		Action:        req.Action,
		TargetARN:     targetARN,
		UTCHour:       g.nowUTC().Hour(),
		BreakGlass:    req.BreakGlass,
	})
	if err != nil {
		g.logger.Error("policy evaluation failure", "correlation_id", req.CorrelationID, "error", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "policy engine unavailable"})
		return
	}

	if !decision.Allowed {
		g.logger.Info("action denied by policy",
			"correlation_id", req.CorrelationID,
			"principal", req.Principal,
			"role", req.Role,
			"action", req.Action,
			"reason", decision.Reason,
		)
		writeJSON(w, http.StatusForbidden, ActionResponse{
			CorrelationID: req.CorrelationID,
			Status:        "denied",
			PolicyReason:  decision.Reason,
		})
		return
	}

	switch req.Action {
	case "iam:AttachRolePolicy":
		if strings.TrimSpace(req.RoleName) == "" || strings.TrimSpace(req.PolicyARN) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role_name and policy_arn are required"})
			return
		}
		if err := g.awsClient.AttachRolePolicy(r.Context(), req.CorrelationID, req.RoleName, req.PolicyARN); err != nil {
			g.logger.Error("iam AttachRolePolicy failed", "correlation_id", req.CorrelationID, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		g.logger.Info("attached iam role policy",
			"correlation_id", req.CorrelationID,
			"principal", req.Principal,
			"role_name", req.RoleName,
			"policy_arn", req.PolicyARN,
			"break_glass", req.BreakGlass.Enabled,
		)
		writeJSON(w, http.StatusOK, ActionResponse{
			CorrelationID: req.CorrelationID,
			Status:        "executed",
			PolicyReason:  decision.Reason,
		})

	case "iam:DetachRolePolicy":
		if strings.TrimSpace(req.RoleName) == "" || strings.TrimSpace(req.PolicyARN) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role_name and policy_arn are required"})
			return
		}
		if err := g.awsClient.DetachRolePolicy(r.Context(), req.CorrelationID, req.RoleName, req.PolicyARN); err != nil {
			g.logger.Error("iam DetachRolePolicy failed", "correlation_id", req.CorrelationID, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		g.logger.Info("detached iam role policy",
			"correlation_id", req.CorrelationID,
			"principal", req.Principal,
			"role_name", req.RoleName,
			"policy_arn", req.PolicyARN,
		)
		writeJSON(w, http.StatusOK, ActionResponse{
			CorrelationID: req.CorrelationID,
			Status:        "executed",
			PolicyReason:  decision.Reason,
		})

	case "sts:AssumeRole":
		if strings.TrimSpace(req.RoleARN) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role_arn is required"})
			return
		}
		sessName := req.SessionName
		if sessName == "" {
			sessName = "gateway-session"
		}
		creds, err := g.awsClient.AssumeRole(r.Context(), req.CorrelationID, req.RoleARN, sessName, req.DurationSeconds, req.BreakGlass.Enabled)
		if err != nil {
			g.logger.Error("sts AssumeRole failed", "correlation_id", req.CorrelationID, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		g.logger.Info("minted sts assume-role credentials",
			"correlation_id", req.CorrelationID,
			"principal", req.Principal,
			"role_arn", req.RoleARN,
			"grace_extended", creds.GraceExtended,
		)
		writeJSON(w, http.StatusOK, ActionResponse{
			CorrelationID: req.CorrelationID,
			Status:        "executed",
			PolicyReason:  decision.Reason,
			Credentials:   &creds,
		})

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errors.New("unsupported action").Error()})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
