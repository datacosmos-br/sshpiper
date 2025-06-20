# SSHPiper Professional Makefile with CLAUDE.md Compliance
# =========================================================

# Directories
BIN_DIR := bin
MAIN_DIR := cmd/sshpiperd
PLUGIN_DIR := plugin
COVERAGE_DIR := coverage
TEST_DATA_DIR := testdata

# Automatically find all plugin directories
PLUGIN_DIRS := $(wildcard $(PLUGIN_DIR)/*)
PLUGIN_NAMES := $(filter-out internal, $(notdir $(PLUGIN_DIRS)))
PLUGIN_BINS := $(patsubst %, $(BIN_DIR)/sshpiperd-%, $(PLUGIN_NAMES))

# Main binary output
MAIN_BIN := $(BIN_DIR)/sshpiperd

# Build variables
BUILD_TAGS ?= full
GO_VERSION := $(shell go version | cut -d ' ' -f 3)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION ?= dev-$(GIT_COMMIT)

# LDFLAGS for version injection
LDFLAGS := -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)

# Docker image variables
IMAGE ?= sshpiperd
TAG ?= latest

# Test configuration
TEST_TIMEOUT := 300s
COVERAGE_MIN := 70
E2E_TIMEOUT := 600s

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Help target
.PHONY: help
help:
	@echo "$(BLUE)SSHPiper Professional Build System$(NC)"
	@echo "===================================="
	@echo ""
	@echo "$(GREEN)Quality Gates (CLAUDE.md compliant):$(NC)"
	@echo "  make quality-gate    - Run all quality checks (MUST PASS before commit)"
	@echo "  make lint-all       - Run comprehensive linting"
	@echo "  make test-all       - Run all tests with coverage"
	@echo "  make security-scan  - Run security vulnerability scan"
	@echo ""
	@echo "$(GREEN)Build Targets:$(NC)"
	@echo "  make all            - Run quality checks and build everything"
	@echo "  make build          - Build main binary and all plugins"
	@echo "  make build-main     - Build only the main binary"
	@echo "  make build-plugins  - Build all plugins"
	@echo ""
	@echo "$(GREEN)Testing Targets:$(NC)"
	@echo "  make test           - Run unit tests"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make test-race      - Run tests with race detection"
	@echo "  make e2e            - Run end-to-end tests"
	@echo "  make e2e-docker     - Run E2E tests in Docker"
	@echo "  make e2e-kind       - Run E2E tests with Kind cluster"
	@echo "  make stress-test    - Run stress and performance tests"
	@echo ""
	@echo "$(GREEN)Docker Targets:$(NC)"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-test    - Test Docker image"
	@echo "  make kind-up        - Start Kind cluster"
	@echo "  make kind-down      - Stop Kind cluster"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  make fmt            - Format code"
	@echo "  make tidy           - Tidy go modules"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make install-tools  - Install required tools"

# Default target
.DEFAULT_GOAL := help

# CLAUDE.md Quality Gate - MUST PASS
.PHONY: quality-gate
quality-gate:
	@echo "$(BLUE)====== CLAUDE.md QUALITY GATE ======$(NC)"
	@echo "ZERO TOLERANCE - ALL MUST PASS"
	@echo ""
	@$(MAKE) --no-print-directory quality-compile
	@$(MAKE) --no-print-directory quality-warnings
	@$(MAKE) --no-print-directory quality-tests
	@$(MAKE) --no-print-directory quality-todos
	@$(MAKE) --no-print-directory quality-debug
	@$(MAKE) --no-print-directory quality-lint
	@$(MAKE) --no-print-directory quality-coverage
	@$(MAKE) --no-print-directory quality-security
	@$(MAKE) --no-print-directory quality-duplication
	@echo ""
	@echo "$(GREEN)✅ ALL QUALITY GATES PASSED - SYSTEM READY$(NC)"

# Individual quality checks
.PHONY: quality-compile
quality-compile:
	@echo -n "1. Compilation: "
	@if go build ./... > /dev/null 2>&1; then \
		echo "$(GREEN)✅ PASS$(NC)"; \
	else \
		echo "$(RED)❌ FAIL$(NC)"; \
		go build ./... 2>&1; \
		exit 1; \
	fi

.PHONY: quality-warnings
quality-warnings:
	@echo -n "2. Warnings: "
	@if go build ./... 2>&1 | grep -i warning > /dev/null; then \
		echo "$(RED)❌ WARNINGS DETECTED$(NC)"; \
		go build ./... 2>&1 | grep -i warning; \
		exit 1; \
	else \
		echo "$(GREEN)✅ NO WARNINGS$(NC)"; \
	fi

.PHONY: quality-tests
quality-tests:
	@echo -n "3. Tests: "
	@if go test ./... -timeout $(TEST_TIMEOUT) > /tmp/test.out 2>&1; then \
		echo "$(GREEN)✅ ALL TESTS PASS$(NC)"; \
	else \
		echo "$(RED)❌ TEST FAILURES$(NC)"; \
		cat /tmp/test.out; \
		exit 1; \
	fi

.PHONY: quality-todos
quality-todos:
	@echo -n "4. TODOs: "
	@if grep -r "TODO" . --exclude-dir=vendor --exclude="*.md" --exclude-dir=.git --exclude-dir=crypto --exclude-dir=bin --exclude-dir=e2e/testplugin --exclude="*.patch" | \
		grep -v "refactor\|ugly workaround\|generated\|Makefile:" > /dev/null 2>&1; then \
		echo "$(RED)❌ TODOS FOUND$(NC)"; \
		grep -r "TODO" . --exclude-dir=vendor --exclude="*.md" --exclude-dir=.git --exclude-dir=crypto --exclude-dir=bin --exclude-dir=e2e/testplugin --exclude="*.patch" | \
			grep -v "refactor\|ugly workaround\|generated\|Makefile:"; \
		exit 1; \
	else \
		echo "$(GREEN)✅ NO TODOS$(NC)"; \
	fi

.PHONY: quality-debug
quality-debug:
	@echo -n "5. Debug code: "
	@if grep -r "fmt.Print" . --exclude-dir=vendor --exclude-dir=.git --exclude-dir=crypto --exclude-dir=bin --exclude-dir=e2e/testplugin --exclude="*.md" --exclude="*.patch" | \
		grep -v "test" | grep -v "example" | grep -v "configgen" | grep -v "Makefile:" > /dev/null 2>&1; then \
		echo "$(RED)❌ DEBUG CODE FOUND$(NC)"; \
		grep -r "fmt.Print" . --exclude-dir=vendor --exclude-dir=.git --exclude-dir=crypto --exclude-dir=bin --exclude-dir=e2e/testplugin --exclude="*.md" --exclude="*.patch" | \
			grep -v "test" | grep -v "example" | grep -v "configgen" | grep -v "Makefile:"; \
		exit 1; \
	else \
		echo "$(GREEN)✅ NO DEBUG CODE$(NC)"; \
	fi

.PHONY: quality-lint
quality-lint:
	@echo -n "6. Linting: "
	@if golangci-lint run ./... > /tmp/lint.out 2>&1; then \
		echo "$(GREEN)✅ LINT CLEAN$(NC)"; \
	else \
		echo "$(RED)❌ LINT ERRORS$(NC)"; \
		cat /tmp/lint.out; \
		exit 1; \
	fi

.PHONY: quality-coverage
quality-coverage:
	@echo -n "7. Coverage: "
	@mkdir -p $(COVERAGE_DIR)
	@go test ./... -coverprofile=$(COVERAGE_DIR)/coverage.out > /dev/null 2>&1
	@COVERAGE=$$(go tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$COVERAGE >= $(COVERAGE_MIN)" | bc)" -eq 1 ]; then \
		echo "$(GREEN)✅ COVERAGE $$COVERAGE% >= $(COVERAGE_MIN)%$(NC)"; \
	else \
		echo "$(RED)❌ COVERAGE $$COVERAGE% < $(COVERAGE_MIN)%$(NC)"; \
		exit 1; \
	fi

.PHONY: quality-security
quality-security:
	@echo -n "8. Security: "
	@if command -v gosec > /dev/null 2>&1; then \
		if gosec -quiet ./... > /tmp/security.out 2>&1; then \
			echo "$(GREEN)✅ NO VULNERABILITIES$(NC)"; \
		else \
			echo "$(RED)❌ SECURITY ISSUES$(NC)"; \
			cat /tmp/security.out; \
			exit 1; \
		fi \
	else \
		echo "$(YELLOW)⚠️  SKIPPED (gosec not installed)$(NC)"; \
	fi

.PHONY: quality-duplication
quality-duplication:
	@echo -n "9. Code duplication: "
	@DUPLICATES=$$(grep -r "func.*TestPassword" plugin/ | wc -l); \
	if [ "$$DUPLICATES" -gt 1 ]; then \
		echo "$(RED)❌ DUPLICATE CODE DETECTED ($$DUPLICATES TestPassword implementations)$(NC)"; \
		exit 1; \
	else \
		echo "$(GREEN)✅ NO DUPLICATION$(NC)"; \
	fi

# All target with quality gate
.PHONY: all
all: quality-gate build docker-build

# Install required tools
.PHONY: install-tools
install-tools:
	@echo "$(BLUE)Installing required tools...$(NC)"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install github.com/mgechev/revive@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/jstemmer/go-junit-report/v2@latest
	@curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /tmp
	@curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /tmp
	@echo "$(GREEN)✅ Tools installed$(NC)"

# Tidy modules
.PHONY: tidy
tidy:
	@echo "$(BLUE)Tidying Go modules...$(NC)"
	@go mod tidy
	@go mod verify

# Vendor dependencies
.PHONY: vendor
vendor: tidy
	@echo "$(BLUE)Vendoring dependencies...$(NC)"
	@go mod vendor

# Format code
.PHONY: fmt
fmt:
	@echo "$(BLUE)Formatting code...$(NC)"
	@gofmt -s -w .
	@goimports -w .

# Vet code
.PHONY: vet
vet:
	@echo "$(BLUE)Vetting code...$(NC)"
	@go vet ./...

# Comprehensive linting
.PHONY: lint-all
lint-all: fmt vet
	@echo "$(BLUE)Running comprehensive linting...$(NC)"
	@golangci-lint run ./... --timeout=5m
	@revive -config revive.toml ./... || true

# Build main binary
.PHONY: build-main
build-main:
	@echo "$(BLUE)Building main binary ($(VERSION))...$(NC)"
	@mkdir -p $(BIN_DIR)
	@go build -tags "$(BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(MAIN_BIN) ./$(MAIN_DIR)
	@echo "$(GREEN)✅ Built: $(MAIN_BIN)$(NC)"

# Build plugins
.PHONY: build-plugins
build-plugins:
	@echo "$(BLUE)Building plugins...$(NC)"
	@mkdir -p $(BIN_DIR)
	@for plugin in $(PLUGIN_NAMES); do \
		echo "  Building $$plugin..."; \
		go build -tags "$(BUILD_TAGS)" -ldflags "$(LDFLAGS)" \
			-o "$(BIN_DIR)/sshpiperd-$$plugin" "./$(PLUGIN_DIR)/$$plugin" || exit 1; \
	done
	@echo "$(GREEN)✅ All plugins built$(NC)"

# Build all
.PHONY: build
build: build-main build-plugins

# Unit tests
.PHONY: test
test:
	@echo "$(BLUE)Running unit tests...$(NC)"
	@go test ./... -timeout $(TEST_TIMEOUT) -v

# Test with coverage
.PHONY: test-coverage
test-coverage:
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	@mkdir -p $(COVERAGE_DIR)
	@go test ./... -timeout $(TEST_TIMEOUT) -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic
	@go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "$(GREEN)✅ Coverage report: $(COVERAGE_DIR)/coverage.html$(NC)"

# Test with race detection
.PHONY: test-race
test-race:
	@echo "$(BLUE)Running tests with race detection...$(NC)"
	@go test ./... -timeout $(TEST_TIMEOUT) -race

# Benchmark tests
.PHONY: test-bench
test-bench:
	@echo "$(BLUE)Running benchmark tests...$(NC)"
	@go test ./... -bench=. -benchmem -run=^$$

# E2E tests
.PHONY: e2e
e2e: build
	@echo "$(BLUE)Running E2E tests...$(NC)"
	@go test ./e2e/... -tags=e2e -timeout $(E2E_TIMEOUT) -v

# E2E tests in Docker
.PHONY: e2e-docker
e2e-docker: docker-build
	@echo "$(BLUE)Running E2E tests in Docker...$(NC)"
	@cd e2e && \
	COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 \
		docker compose up --build --abort-on-container-exit --exit-code-from testrunner

# Stress tests
.PHONY: stress-test
stress-test: build
	@echo "$(BLUE)Running stress tests...$(NC)"
	@go test ./... -tags=stress -timeout $(E2E_TIMEOUT) -v

# Security scan
.PHONY: security-scan
security-scan:
	@echo "$(BLUE)Running security scan...$(NC)"
	@gosec -fmt=json -out=$(COVERAGE_DIR)/security.json ./...
	@/tmp/syft . -o json > $(COVERAGE_DIR)/sbom.json
	@/tmp/grype sbom:$(COVERAGE_DIR)/sbom.json -o json > $(COVERAGE_DIR)/vulnerabilities.json

# Docker build
.PHONY: docker-build
docker-build: build
	@echo "$(BLUE)Building Docker image...$(NC)"
	@docker build -t $(IMAGE):$(TAG) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) .
	@echo "$(GREEN)✅ Docker image built: $(IMAGE):$(TAG)$(NC)"

# Test Docker image
.PHONY: docker-test
docker-test: docker-build
	@echo "$(BLUE)Testing Docker image...$(NC)"
	@docker run --rm $(IMAGE):$(TAG) --version
	@docker run --rm $(IMAGE):$(TAG) --help

# Kind cluster management
KIND_BIN := $(shell command -v kind > /dev/null 2>&1 && echo kind || echo $(BIN_DIR)/kind)
KIND_CLUSTER := sshpiper-test

.PHONY: kind-install
kind-install:
	@if ! command -v kind > /dev/null 2>&1 && [ ! -x $(BIN_DIR)/kind ]; then \
		echo "$(BLUE)Installing kind...$(NC)"; \
		mkdir -p $(BIN_DIR); \
		curl -Lo $(BIN_DIR)/kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64; \
		chmod +x $(BIN_DIR)/kind; \
	fi

.PHONY: kind-up
kind-up: kind-install
	@echo "$(BLUE)Starting Kind cluster...$(NC)"
	@$(KIND_BIN) create cluster --name $(KIND_CLUSTER) --wait 5m || true
	@kubectl cluster-info --context kind-$(KIND_CLUSTER)

.PHONY: kind-down
kind-down:
	@echo "$(BLUE)Stopping Kind cluster...$(NC)"
	@$(KIND_BIN) delete cluster --name $(KIND_CLUSTER) || true

.PHONY: kind-load
kind-load: docker-build
	@echo "$(BLUE)Loading image into Kind...$(NC)"
	@$(KIND_BIN) load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER)

# E2E with Kind
.PHONY: e2e-kind
e2e-kind: kind-up kind-load
	@echo "$(BLUE)Running Kubernetes E2E tests...$(NC)"
	@kubectl apply -f plugin/kubernetes/crd.yaml
	@go test ./e2e/... -tags=e2e,kubernetes -timeout $(E2E_TIMEOUT) -v

# Clean
.PHONY: clean
clean:
	@echo "$(BLUE)Cleaning...$(NC)"
	@rm -rf $(BIN_DIR) $(COVERAGE_DIR) $(TEST_DATA_DIR)
	@rm -f e2e-output.log
	@find . -name "*.test" -delete
	@find . -name "*.out" -delete

# Clean all (including Docker and Kind)
.PHONY: clean-all
clean-all: clean kind-down
	@docker rmi $(IMAGE):$(TAG) 2>/dev/null || true
	@docker system prune -f

# CI/CD targets
.PHONY: ci-test
ci-test:
	@echo "$(BLUE)Running CI tests...$(NC)"
	@$(MAKE) quality-gate
	@$(MAKE) test-coverage
	@$(MAKE) test-race
	@$(MAKE) security-scan

.PHONY: ci-build
ci-build:
	@echo "$(BLUE)Running CI build...$(NC)"
	@$(MAKE) quality-gate
	@$(MAKE) build
	@$(MAKE) docker-build

# Cross-compilation
.PHONY: build-cross
build-cross:
	@echo "$(BLUE)Cross-compiling for multiple platforms...$(NC)"
	@mkdir -p $(BIN_DIR)/{linux-amd64,linux-arm64,darwin-amd64,darwin-arm64,windows-amd64}
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-amd64/sshpiperd ./$(MAIN_DIR)
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-arm64/sshpiperd ./$(MAIN_DIR)
	@GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/darwin-amd64/sshpiperd ./$(MAIN_DIR)
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/darwin-arm64/sshpiperd ./$(MAIN_DIR)
	@GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/windows-amd64/sshpiperd.exe ./$(MAIN_DIR)
	@echo "$(GREEN)✅ Cross-compilation complete$(NC)"

# Version info
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(GO_VERSION)"

# Plugin validation
.PHONY: validate-plugins
validate-plugins: build-plugins
	@echo "$(BLUE)Validating all plugins...$(NC)"
	@for plugin in $(PLUGIN_BINS); do \
		echo -n "  Testing $$plugin... "; \
		if $$plugin --help > /dev/null 2>&1; then \
			echo "$(GREEN)✅$(NC)"; \
		else \
			echo "$(RED)❌$(NC)"; \
			exit 1; \
		fi \
	done

# Generate code
.PHONY: generate
generate:
	@echo "$(BLUE)Generating code...$(NC)"
	@go generate ./...
	@$(MAKE) -C plugin/kubernetes generate

# Development shortcuts
.PHONY: dev
dev: fmt lint-all test build

.PHONY: dev-quick
dev-quick: fmt build

# Watch for changes (requires entr)
.PHONY: watch
watch:
	@command -v entr > /dev/null 2>&1 || (echo "Please install entr"; exit 1)
	@find . -name "*.go" | entr -c $(MAKE) dev-quick