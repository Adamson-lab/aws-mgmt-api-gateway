package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/auth"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/cloud_client"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/policy"
	"github.com/Adamson-lab/aws-mgmt-api-gateway/internal/server"
)

func probeEndpoint(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	awsEndpoint := envOrDefault("AWS_ENDPOINT_URL", "http://localhost:4566")
	awsRegion := envOrDefault("AWS_REGION", "us-east-1")
	opaURL := envOrDefault("OPA_URL", "http://localhost:8181")
	hmacSecret := envOrDefault("WEBHOOK_HMAC_SECRET", "local-dev-signing-secret")
	addr := envOrDefault("LISTEN_ADDR", ":8080")

	ctx := context.Background()
	awsClient, err := cloud_client.NewAWSManagementClient(ctx, awsRegion, awsEndpoint, logger)
	if err != nil {
		logger.Error("failed to initialize aws management client", "error", err)
		os.Exit(1)
	}

	verifier := auth.NewVerifier(hmacSecret, 5*time.Minute)
	evaluator := policy.NewEvaluator(opaURL, 3*time.Second)

	probeClient := &http.Client{Timeout: 2 * time.Second}
	healthProbe := func(pCtx context.Context) (bool, bool) {
		lsOK := probeEndpoint(pCtx, probeClient, awsEndpoint+"/_localstack/health")
		opaOK := probeEndpoint(pCtx, probeClient, opaURL+"/health")
		return lsOK, opaOK
	}

	gw := server.NewGateway(verifier, evaluator, awsClient, healthProbe, logger)
	srv := &http.Server{
		Addr:              addr,
		Handler:           gw.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("starting aws-mgmt-api-gateway", "addr", addr, "aws_endpoint", awsEndpoint, "opa_url", opaURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server exited with error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info("gateway shutdown complete")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
