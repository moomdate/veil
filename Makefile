.DEFAULT_GOAL := help
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-10s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build ./bin/veil (protected with the hardened runtime on macOS)
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/veil ./cmd/veil
	@if [ "$$(uname)" = Darwin ]; then codesign --sign - --force --options runtime bin/veil; fi

.PHONY: test
test: ## Run all tests with the race detector
	go test -race ./...

.PHONY: cover
cover: ## Run tests and report coverage across packages
	go test -race -coverpkg=./internal/... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: fuzz
fuzz: ## Fuzz the redactor (FUZZTIME=2m to change duration)
	go test ./internal/redact -run '^$$' -fuzz FuzzNeverLeaks -fuzztime $(or $(FUZZTIME),1m)

.PHONY: lint
lint: ## Run golangci-lint and govulncheck
	golangci-lint run
	govulncheck ./...

.PHONY: check
check: lint test ## Everything CI runs

.PHONY: clean
clean: ## Remove build output
	rm -rf bin dist coverage.out
