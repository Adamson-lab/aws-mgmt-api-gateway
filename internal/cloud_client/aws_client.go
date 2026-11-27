package cloud_client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type IAMAPI interface {
	AttachRolePolicy(ctx context.Context, params *iam.AttachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.AttachRolePolicyOutput, error)
	DetachRolePolicy(ctx context.Context, params *iam.DetachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
}

type STSAPI interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

type AWSManagementClient struct {
	iamClient IAMAPI
	stsClient STSAPI
	retry     RetryPolicy
	logger    *slog.Logger
}

type AssumeRoleResult struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
	GraceExtended   bool      `json:"grace_extended"`
}

func NewAWSManagementClient(ctx context.Context, region, endpointURL string, logger *slog.Logger) (*AWSManagementClient, error) {
	if region == "" {
		region = "us-east-1"
	}
	if logger == nil {
		logger = slog.Default()
	}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if endpointURL != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var iamOpts []func(*iam.Options)
	var stsOpts []func(*sts.Options)
	if endpointURL != "" {
		iamOpts = append(iamOpts, func(o *iam.Options) { o.BaseEndpoint = aws.String(endpointURL) })
		stsOpts = append(stsOpts, func(o *sts.Options) { o.BaseEndpoint = aws.String(endpointURL) })
	}

	return &AWSManagementClient{
		iamClient: iam.NewFromConfig(cfg, iamOpts...),
		stsClient: sts.NewFromConfig(cfg, stsOpts...),
		retry: RetryPolicy{
			MaxAttempts: 4,
			BaseDelay:   100 * time.Millisecond,
			MaxDelay:    2 * time.Second,
		},
		logger: logger,
	}, nil
}

func NewWithClients(iamClient IAMAPI, stsClient STSAPI, retry RetryPolicy, logger *slog.Logger) *AWSManagementClient {
	if logger == nil {
		logger = slog.Default()
	}
	if retry.MaxAttempts <= 0 {
		retry.MaxAttempts = 4
	}
	if retry.BaseDelay <= 0 {
		retry.BaseDelay = 50 * time.Millisecond
	}
	if retry.MaxDelay <= 0 {
		retry.MaxDelay = 1 * time.Second
	}
	return &AWSManagementClient{
		iamClient: iamClient,
		stsClient: stsClient,
		retry:     retry,
		logger:    logger,
	}
}

func isRetryableAWSError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		if code == "Throttling" || code == "ThrottlingException" || code == "RequestLimitExceeded" || code == "ServiceUnavailable" {
			return true
		}
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		status := respErr.HTTPStatusCode()
		if status == 429 || status == 503 || status == 502 || status == 504 {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "ThrottlingException") || strings.Contains(msg, "503")
}

func (c *AWSManagementClient) withRetry(ctx context.Context, correlationID, operation string, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= c.retry.MaxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !isRetryableAWSError(lastErr) || attempt == c.retry.MaxAttempts {
			return lastErr
		}
		backoff := time.Duration(float64(c.retry.BaseDelay) * math.Pow(2, float64(attempt-1)))
		if backoff > c.retry.MaxDelay {
			backoff = c.retry.MaxDelay
		}
		c.logger.Warn("retrying upstream aws api after transient failure",
			"correlation_id", correlationID,
			"operation", operation,
			"attempt", attempt,
			"backoff_ms", backoff.Milliseconds(),
			"error", lastErr.Error(),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return lastErr
}

func (c *AWSManagementClient) AttachRolePolicy(ctx context.Context, correlationID, roleName, policyARN string) error {
	return c.withRetry(ctx, correlationID, "iam:AttachRolePolicy", func() error {
		_, err := c.iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
			RoleName:  aws.String(roleName),
			PolicyArn: aws.String(policyARN),
		})
		return err
	})
}

func (c *AWSManagementClient) DetachRolePolicy(ctx context.Context, correlationID, roleName, policyARN string) error {
	return c.withRetry(ctx, correlationID, "iam:DetachRolePolicy", func() error {
		_, err := c.iamClient.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			RoleName:  aws.String(roleName),
			PolicyArn: aws.String(policyARN),
		})
		return err
	})
}

func (c *AWSManagementClient) ListAttachedRolePolicies(ctx context.Context, roleName string) ([]string, error) {
	out, err := c.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, err
	}
	var arns []string
	for _, p := range out.AttachedPolicies {
		if p.PolicyArn != nil {
			arns = append(arns, *p.PolicyArn)
		}
	}
	return arns, nil
}

// AssumeRole mints temporary STS credentials and automatically grants a 15-minute grace extension
// when breakGlassActive is true so an engineer's session does not drop mid-incident.
func (c *AWSManagementClient) AssumeRole(ctx context.Context, correlationID, roleARN, sessionName string, durationSeconds int32, breakGlassActive bool) (AssumeRoleResult, error) {
	if durationSeconds < 900 {
		durationSeconds = 900
	}
	graceExtended := false
	if breakGlassActive && durationSeconds < 1800 {
		durationSeconds += 900 // +15m active-incident grace extension
		graceExtended = true
	}

	var out *sts.AssumeRoleOutput
	err := c.withRetry(ctx, correlationID, "sts:AssumeRole", func() error {
		var callErr error
		out, callErr = c.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(roleARN),
			RoleSessionName: aws.String(sessionName),
			DurationSeconds: aws.Int32(durationSeconds),
		})
		return callErr
	})
	if err != nil {
		return AssumeRoleResult{}, err
	}
	if out == nil || out.Credentials == nil {
		return AssumeRoleResult{}, fmt.Errorf("sts AssumeRole returned empty credentials")
	}

	return AssumeRoleResult{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
		Expiration:      aws.ToTime(out.Credentials.Expiration).UTC(),
		GraceExtended:   graceExtended,
	}, nil
}
