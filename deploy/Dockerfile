FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/aws-mgmt-api-gateway ./cmd/gateway

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /out/aws-mgmt-api-gateway /usr/local/bin/aws-mgmt-api-gateway
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aws-mgmt-api-gateway"]
