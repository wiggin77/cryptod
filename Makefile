.PHONY: help test test-verbose test-race test-cover test-security bench fmt lint clean check-fmt vet build-cli install-cli

# Build variables
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO := go
GOFLAGS ?=
GOBIN := $(shell go env GOPATH)/bin
CLI_BINARY := example/cmd/crypt/crypt

## help: Display this help message
help:
	@echo "cryptod - Makefile Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^## ' Makefile | sed 's/##/  /'

## test: Run all tests
test:
	$(GO) test $(GOFLAGS) ./...

## test-verbose: Run all tests with verbose output
test-verbose:
	$(GO) test $(GOFLAGS) -v ./...

## test-race: Run tests with race detector
test-race:
	$(GO) test $(GOFLAGS) -race ./...

## test-cover: Run tests with coverage report
test-cover:
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## test-security: Run security tests with verbose output
test-security:
	@echo "Running security tests..."
	$(GO) test $(GOFLAGS) -v -run 'TestChunk.*|TestWeak.*|TestNonce.*|TestCLI.*' ./...

## bench: Run benchmarks
bench:
	$(GO) test $(GOFLAGS) -bench=. -benchmem ./...

## fmt: Format all Go files
fmt:
	$(GO) fmt ./...

## check-fmt: Check if Go files are formatted
check-fmt:
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "The following files are not formatted:"; \
		gofmt -l .; \
		exit 1; \
	fi

## vet: Run go vet on all packages
vet:
	$(GO) vet ./...

## lint: Run golangci-lint
lint:
	@test -f $(GOBIN)/golangci-lint || { echo "golangci-lint not installed. Installing..."; $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; }
	$(GOBIN)/golangci-lint run ./...

## check: Run format check, vet, lint, and tests
check: check-fmt vet lint test

## build-cli: Build the crypt CLI tool
build-cli:
	@echo "Building crypt CLI..."
	$(GO) build $(GOFLAGS) -o $(CLI_BINARY) ./example/cmd/crypt
	@echo "Binary created at $(CLI_BINARY)"

## install-cli: Install the crypt CLI tool to GOBIN
install-cli:
	@echo "Installing crypt CLI to $(GOBIN)..."
	$(GO) install $(GOFLAGS) ./example/cmd/crypt
	@echo "Installed to $(GOBIN)/crypt"

## clean: Remove generated files and binaries
clean:
	$(GO) clean
	rm -f coverage.out coverage.html
	rm -f $(CLI_BINARY)
	@echo "Cleaned build artifacts"

## version: Display version information
version:
	@echo "Build Date: $(BUILD_DATE)"
	@echo "Build Hash: $(BUILD_HASH)"
