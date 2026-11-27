package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type BreakGlassRequest struct {
	Enabled       bool   `json:"enabled"`
	IncidentID    string `json:"incident_id"`
	Justification string `json:"justification"`
}

type EvaluationInput struct {
	CorrelationID string            `json:"correlation_id"`
	Principal     string            `json:"principal"`
	Role          string            `json:"role"`
	Action        string            `json:"action"`
	TargetARN     string            `json:"target_arn"`
	UTCHour       int               `json:"utc_hour"`
	BreakGlass    BreakGlassRequest `json:"break_glass"`
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type opaEnvelope struct {
	Result *Decision `json:"result"`
}

type Evaluator struct {
	baseURL    string
	httpClient *http.Client
}

func NewEvaluator(baseURL string, timeout time.Duration) *Evaluator {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Evaluator{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (e *Evaluator) Evaluate(ctx context.Context, in EvaluationInput) (Decision, error) {
	payload := map[string]any{
		"input": in,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return Decision{}, fmt.Errorf("marshal policy input: %w", err)
	}

	url := e.baseURL + "/v1/data/aws/mgmt/api"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return Decision{}, fmt.Errorf("build opa request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if in.CorrelationID != "" {
		req.Header.Set("X-Correlation-ID", in.CorrelationID)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("opa request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("opa returned unexpected status %d", resp.StatusCode)
	}

	var env opaEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return Decision{}, fmt.Errorf("decode opa response: %w", err)
	}
	if env.Result == nil {
		return Decision{}, fmt.Errorf("opa response missing result object")
	}

	return *env.Result, nil
}
