PLUGIN_NAME := vault-plugin-secrets-salesforce
PKG := ./cmd/$(PLUGIN_NAME)
DIST := dist

.PHONY: build build-linux test testacc cover fmt vet deploy-sandbox clean

## build: compile the plugin for the host platform
build:
	go build -o $(DIST)/$(PLUGIN_NAME) $(PKG)

## build-linux: cross-compile for the Vault sandbox container (linux/arm64)
build-linux:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(DIST)/$(PLUGIN_NAME)_linux_arm64 $(PKG)

## test: run unit tests (race detector)
test:
	go test -race ./...

## testacc: run acceptance tests (requires VAULT_ACC=1)
testacc:
	VAULT_ACC=1 go test ./... -v

## cover: report test coverage
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## fmt: format the code
fmt:
	gofmt -w .

## vet: run go vet
vet:
	go vet ./...

## deploy-sandbox: build + register + enable/reload in the lab Vault
deploy-sandbox:
	./scripts/deploy-sandbox.sh

## release: cross-compile all supported platforms + checksums into dist/
release:
	./scripts/build-release.sh $(VERSION)

## clean: remove build artifacts
clean:
	rm -rf $(DIST)
