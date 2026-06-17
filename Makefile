.PHONY: all build test test-race test-e2e test-integration lint clean sync-schemas

# Default target: the pre-push sequence. Lint, run all unit tests with
# the race detector, run the e2e suite, then build. Skips Docker-bound
# integration tests — run `make test-integration` separately when
# Docker is available.
all: lint test-race test-e2e build

VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
  -X github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/version.Version=$(VERSION) \
  -X github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli.Commit=$(COMMIT) \
  -X github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/cli.Date=$(DATE)

build: sync-schemas
	go build -ldflags '$(LDFLAGS)' -o bin/monedula-acl-rbac ./cmd/monedula-acl-rbac

test: sync-schemas
	go test ./...

test-race: sync-schemas
	go test -race ./...

# E2E tests use kfake + httptest fakes; no external dependencies.
test-e2e: sync-schemas
	go test -tags e2e -count=1 ./tests/e2e/...

# Integration tests bring up a real confluentinc/cp-kafka container via
# testcontainers-go. Requires a running Docker daemon. Skipped gracefully
# if Docker is unreachable.
test-integration: sync-schemas
	go test -tags integration -count=1 -v ./tests/integration/...

# Mirrors CI (.github/workflows/ci.yml): golangci-lint v2 runs go vet's checks
# plus the gofmt formatter gate, so `make lint` passing locally means CI's lint
# job passes too. golangci-lint is required — running only `go vet` here would
# let formatting / lint drift through that CI then rejects.
lint:
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "ERROR: golangci-lint not found, but CI runs it (incl. the gofmt gate)."; \
		echo "Install: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2"; \
		exit 1; \
	}
	golangci-lint run ./...

clean:
	go run ./tools/clean-bin

# Keeps the schemas embedded into the binary in sync with the canonical copies
# at the repo root (which docs link to).
sync-schemas:
	go run ./tools/sync-schemas
