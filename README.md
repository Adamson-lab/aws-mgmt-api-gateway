# aws-mgmt-api-gateway

An internal HTTP API gateway in Go (`1.22`) that mediates access to AWS IAM (`AttachRolePolicy`, `DetachRolePolicy`) and AWS STS (`AssumeRole`). Every request is authenticated with HMAC-SHA256 + timestamp replay protection, evaluated against Open Policy Agent (OPA) Rego rules in UTC, logged as structured JSON via `log/slog`, and executed via `aws-sdk-go-v2` with exponential backoff retries.

## Repository Layout (10 Directories)

```text
aws-mgmt-api-gateway/
├── cmd/
│   └── gateway/          # HTTP server entrypoint and dependency health checks
├── internal/
│   ├── auth/             # HMAC-SHA256 signature and timestamp replay verification
│   ├── cloud_client/     # aws-sdk-go-v2 IAM/STS wrapper with exponential backoff
│   ├── policy/           # Open Policy Agent REST evaluation client
│   └── server/           # HTTP handlers, correlation IDs, and structured slog logging
├── policies/             # OPA Rego rules (operating windows + break-glass overrides)
├── deploy/               # Dockerfile and docker-compose.yml (LocalStack + OPA)
├── tests/                # Unit, retry, LocalStack/OPA integration, and benchmark tests
├── DESIGN.md             # Architecture, sequence flow, and failure mode handling
├── Makefile              # make up, make run, make test, make bench, make down
└── README.md
```

## Quickstart

### 1. Start LocalStack and OPA
```bash
make up
```

### 2. Run the Gateway Locally
```bash
make run
```

### 3. Check Dependency Health
```bash
curl -s http://localhost:8080/healthz | jq .
```

### 4. Send a Signed `sts:AssumeRole` Request
```bash
BODY='{"principal":"sre@corp.example","role":"platform-sre","action":"sts:AssumeRole","role_arn":"arn:aws:iam::000000000000:role/demo-role","session_name":"ops-session","duration_seconds":900}'
TS=$(date -u +%s)
SIG="sha256=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac 'local-dev-signing-secret' | awk '{print $2}')"

curl -s -X POST http://localhost:8080/v1/actions   -H "Content-Type: application/json"   -H "X-Timestamp: $TS"   -H "X-Signature-256: $SIG"   -d "$BODY" | jq .
```

## Testing & Benchmarks

Run unit tests (and live integration tests when LocalStack and OPA are running via `make up`):
```bash
make test
```

Run end-to-end HTTP + HMAC + OPA + stubbed AWS dispatch latency benchmarks:
```bash
make bench
```

Tear down LocalStack and OPA containers:
```bash
make down
```
