package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/auth"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/cloud_client"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/policy"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/server"
)

func TestHMACVerifierRejectsMalformedAndExpiredRequests(t *testing.T) {
	secret := "test-hmac-secret"
	v := auth.NewVerifier(secret, 5*time.Minute)
	body := []byte(`{"action":"sts:AssumeRole"}`)
	now := time.Now().UTC().Unix()

	validSig := auth.ComputeSignature([]byte(secret), now, body)
	if err := v.Verify(validSig, strconv.FormatInt(now, 10), body); err != nil {
		t.Fatalf("expected valid signature to pass, got: %v", err)
	}

	if err := v.Verify("sha256=deadbeef", strconv.FormatInt(now, 10), body); !errors.Is(err, auth.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}

	expiredTS := strconv.FormatInt(now-600, 10)
	expiredSig := auth.ComputeSignature([]byte(secret), now-600, body)
	if err := v.Verify(expiredSig, expiredTS, body); !errors.Is(err, auth.ErrTimestampSkew) {
		t.Fatalf("expected ErrTimestampSkew, got: %v", err)
	}
}

type flakyIAMStub struct {
	attempts atomic.Int32
}

func (f *flakyIAMStub) AttachRolePolicy(ctx context.Context, params *iam.AttachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.AttachRolePolicyOutput, error) {
	n := f.attempts.Add(1)
	if n < 3 {
		return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	}
	return &iam.AttachRolePolicyOutput{}, nil
}

func (f *flakyIAMStub) DetachRolePolicy(ctx context.Context, params *iam.DetachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error) {
	return &iam.DetachRolePolicyOutput{}, nil
}

func (f *flakyIAMStub) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{}, nil
}

type stubSTS struct{}

func (s *stubSTS) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	exp := time.Now().UTC().Add(time.Duration(aws.ToInt32(params.DurationSeconds)) * time.Second)
	return &sts.AssumeRoleOutput{
		Credentials: &sts.Credentials{
			AccessKeyId:     aws.String("ASIAEXAMPLE123"),
			SecretAccessKey: aws.String("secret-example"),
			SessionToken:    aws.String("token-example"),
			Expiration:      aws.Time(exp),
		},
	}, nil
}

func TestExponentialBackoffRetriesOnAWSThrottlingException(t *testing.T) {
	stub := &flakyIAMStub{}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	client := cloud_client.NewWithClients(stub, &stubSTS{}, cloud_client.RetryPolicy{
		MaxAttempts: 4,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    50 * time.Millisecond,
	}, logger)

	err := client.AttachRolePolicy(context.Background(), "corr-retry-1", "app-role", "arn:aws:iam::aws:policy/ReadOnlyAccess")
	if err != nil {
		t.Fatalf("expected retry to succeed on 3rd attempt, got: %v", err)
	}
	if got := stub.attempts.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestEndToEndGatewayWithOPAAndLocalStack(t *testing.T) {
	awsEndpoint := os.Getenv("AWS_ENDPOINT_URL")
	opaURL := os.Getenv("OPA_URL")
	if awsEndpoint == "" || opaURL == "" {
		t.Skip("AWS_ENDPOINT_URL or OPA_URL not set; skipping live container integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Verify containers are reachable before executing integration assertions
	httpClient := &http.Client{Timeout: 2 * time.Second}
	if _, err := httpClient.Get(awsEndpoint + "/_localstack/health"); err != nil {
		t.Skipf("LocalStack not reachable at %s: %v", awsEndpoint, err)
	}
	if _, err := httpClient.Get(opaURL + "/health"); err != nil {
		t.Skipf("OPA not reachable at %s: %v", opaURL, err)
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	secret := "integration-signing-secret"
	awsClient, err := cloud_client.NewAWSManagementClient(ctx, "us-east-1", awsEndpoint, logger)
	if err != nil {
		t.Fatalf("failed to create aws client: %v", err)
	}

	// Provision a real IAM role in LocalStack
	cfg, _ := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	rawIAM := iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = aws.String(awsEndpoint) })
	roleName := fmt.Sprintf("gateway-it-role-%d", time.Now().UnixNano())
	trustDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	roleOut, err := rawIAM.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(trustDoc),
	})
	if err != nil {
		t.Fatalf("failed to create IAM role in LocalStack: %v", err)
	}
	defer func() {
		_, _ = rawIAM.DeleteRole(context.Background(), &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
	}()

	gw := server.NewGateway(
		auth.NewVerifier(secret, 5*time.Minute),
		policy.NewEvaluator(opaURL, 3*time.Second),
		awsClient,
		nil,
		logger,
	)
	// Pin gateway UTC clock to 14:00 UTC (inside operating window)
	gw.SetNowUTC(func() time.Time { return time.Date(2026, 11, 27, 14, 0, 0, 0, time.UTC) })
	ts := httptest.NewServer(gw.Routes())
	defer ts.Close()

	sendSigned := func(sigOverride string, payload server.ActionRequest) (*http.Response, []byte) {
		raw, _ := json.Marshal(payload)
		unixTS := time.Now().UTC().Unix()
		sig := auth.ComputeSignature([]byte(secret), unixTS, raw)
		if sigOverride != "" {
			sig = sigOverride
		}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/actions", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Timestamp", strconv.FormatInt(unixTS, 10))
		req.Header.Set("X-Signature-256", sig)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// 1. Malformed HMAC signature -> 401 Unauthorized
	resp401, _ := sendSigned("sha256=invalid", server.ActionRequest{
		Principal: "sre@corp.example",
		Role:      "platform-sre",
		Action:    "iam:AttachRolePolicy",
		RoleName:  roleName,
		PolicyARN: "arn:aws:iam::aws:policy/ReadOnlyAccess",
	})
	if resp401.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp401.StatusCode)
	}

	// 2. Unauthorized role action -> 403 Forbidden from OPA
	resp403, _ := sendSigned("", server.ActionRequest{
		Principal: "auditor@corp.example",
		Role:      "security-auditor",
		Action:    "iam:AttachRolePolicy",
		RoleName:  roleName,
		PolicyARN: "arn:aws:iam::aws:policy/ReadOnlyAccess",
	})
	if resp403.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp403.StatusCode)
	}

	// 3. Authorized iam:AttachRolePolicy -> 200 OK + verify policy is attached in LocalStack IAM
	policyARN := "arn:aws:iam::aws:policy/ReadOnlyAccess"
	resp200, body200 := sendSigned("", server.ActionRequest{
		Principal: "sre@corp.example",
		Role:      "platform-sre",
		Action:    "iam:AttachRolePolicy",
		RoleName:  roleName,
		PolicyARN: policyARN,
	})
	if resp200.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", resp200.StatusCode, string(body200))
	}

	attached, err := awsClient.ListAttachedRolePolicies(ctx, roleName)
	if err != nil {
		t.Fatalf("ListAttachedRolePolicies failed: %v", err)
	}
	if len(attached) != 1 || attached[0] != policyARN {
		t.Fatalf("expected policy %s attached in LocalStack IAM, got %v", policyARN, attached)
	}

	// 4. Off-hours (02:00 UTC) with break-glass sts:AssumeRole -> 200 OK + +15m grace extension
	gw.SetNowUTC(func() time.Time { return time.Date(2026, 11, 27, 2, 0, 0, 0, time.UTC) })
	respBG, bodyBG := sendSigned("", server.ActionRequest{
		Principal:       "sre@corp.example",
		Role:            "platform-sre",
		Action:          "sts:AssumeRole",
		RoleARN:         aws.ToString(roleOut.Role.Arn),
		SessionName:     "inc-9042-session",
		DurationSeconds: 900,
		BreakGlass: policy.BreakGlassRequest{
			Enabled:       true,
			IncidentID:    "INC-9042",
			Justification: "Emergency database failover credential elevation",
		},
	})
	if respBG.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for break-glass AssumeRole, got %d: %s", respBG.StatusCode, string(bodyBG))
	}
	var bgOut server.ActionResponse
	_ = json.Unmarshal(bodyBG, &bgOut)
	if bgOut.Credentials == nil || !bgOut.Credentials.GraceExtended || bgOut.Credentials.AccessKeyID == "" {
		t.Fatalf("expected grace-extended STS credentials, got %+v", bgOut.Credentials)
	}

	// 5. Detach policy to verify clean teardown state in LocalStack IAM
	gw.SetNowUTC(func() time.Time { return time.Date(2026, 11, 27, 14, 0, 0, 0, time.UTC) })
	respDetach, _ := sendSigned("", server.ActionRequest{
		Principal: "sre@corp.example",
		Role:      "platform-sre",
		Action:    "iam:DetachRolePolicy",
		RoleName:  roleName,
		PolicyARN: policyARN,
	})
	if respDetach.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on DetachRolePolicy, got %d", respDetach.StatusCode)
	}
	afterDetach, _ := awsClient.ListAttachedRolePolicies(ctx, roleName)
	if len(afterDetach) != 0 {
		t.Fatalf("expected 0 attached policies after detach, got %v", afterDetach)
	}
}

func BenchmarkGatewayAuthorizationAndAWSDispatch(b *testing.B) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": policy.Decision{Allowed: true, Reason: "benchmark allow"},
		})
	}))
	defer opaSrv.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	secret := "bench-secret"
	awsClient := cloud_client.NewWithClients(&flakyIAMStub{}, &stubSTS{}, cloud_client.RetryPolicy{MaxAttempts: 1}, logger)
	gw := server.NewGateway(
		auth.NewVerifier(secret, 5*time.Minute),
		policy.NewEvaluator(opaSrv.URL, 2*time.Second),
		awsClient,
		nil,
		logger,
	)
	gw.SetNowUTC(func() time.Time { return time.Date(2026, 11, 27, 14, 0, 0, 0, time.UTC) })
	ts := httptest.NewServer(gw.Routes())
	defer ts.Close()

	payload, _ := json.Marshal(server.ActionRequest{
		Principal:       "bench@corp.example",
		Role:            "platform-sre",
		Action:          "sts:AssumeRole",
		RoleARN:         "arn:aws:iam::123456789012:role/bench-role",
		DurationSeconds: 900,
	})
	client := &http.Client{Timeout: 2 * time.Second}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nowTS := time.Now().UTC().Unix()
		sig := auth.ComputeSignature([]byte(secret), nowTS, payload)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/actions", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Timestamp", strconv.FormatInt(nowTS, 10))
		req.Header.Set("X-Signature-256", sig)
		resp, err := client.Do(req)
		if err != nil {
			b.Fatalf("bench request failed: %v", err)
		}
		_ = resp.Body.Close()
	}
}
