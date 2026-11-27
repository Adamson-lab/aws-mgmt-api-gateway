SHELL := /bin/bash
COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: up down run test bench tidy build

up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

down:
	docker compose -f $(COMPOSE_FILE) down -v

tidy:
	go mod tidy

build:
	go build -o bin/aws-mgmt-api-gateway ./cmd/gateway

run:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	WEBHOOK_HMAC_SECRET=local-dev-signing-secret \
	go run ./cmd/gateway

test:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	WEBHOOK_HMAC_SECRET=local-dev-signing-secret \
	go test -v -race ./...

bench:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	WEBHOOK_HMAC_SECRET=local-dev-signing-secret \
	go test -bench=. -benchmem ./tests/...
