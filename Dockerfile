# syntax=docker/dockerfile:1

# Build stage: compile the plugin for the target platform. BuildKit provides
# TARGETOS/TARGETARCH automatically for each requested platform.
FROM --platform=$BUILDPLATFORM golang:1.25 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/vault-plugin-secrets-salesforce ./cmd/vault-plugin-secrets-salesforce

# Final stage.
FROM alpine:3.21

# Salesforce token requests need trusted root CAs for outbound TLS.
RUN apk add --no-cache ca-certificates

LABEL org.opencontainers.image.title="vault-plugin-secrets-salesforce"
LABEL org.opencontainers.image.description="HashiCorp Vault secrets engine for Salesforce OAuth 2.0 access tokens"
LABEL org.opencontainers.image.source="https://github.com/DarthVaderRC/vault-plugin-secrets-salesforce"
LABEL org.opencontainers.image.licenses="MPL-2.0"

COPY --from=builder /out/vault-plugin-secrets-salesforce /bin/vault-plugin-secrets-salesforce

ENTRYPOINT ["/bin/vault-plugin-secrets-salesforce"]
