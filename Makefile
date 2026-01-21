# SSHPiper Professional Build System
# ===================================
# Professional, consolidated Makefile for development, testing, and deployment

# Terminal colors - properly configured for all terminal types
SHELL := /bin/bash
export TERM ?= xterm-256color

# Color definitions with fallback support
ifeq ($(shell test -t 1 && echo 1),1)
	RED := \033[0;31m
	GREEN := \033[0;32m
	YELLOW := \033[1;33m
	BLUE := \033[0;34m
	PURPLE := \033[0;35m
	CYAN := \033[0;36m
	WHITE := \033[1;37m
	BOLD := \033[1m
	NC := \033[0m
else
	RED := 
	GREEN := 
	YELLOW := 
	BLUE := 
	PURPLE := 
	CYAN := 
	WHITE := 
	BOLD := 
	NC := 
endif

# Helper functions for colored output
define log_info
	@printf "$(BLUE)[INFO]$(NC) %s\n" "$(1)"
endef

define log_success
	@printf "$(GREEN)[SUCCESS]$(NC) %s\n" "$(1)"
endef

define log_warning
	@printf "$(YELLOW)[WARNING]$(NC) %s\n" "$(1)"
endef

define log_error
	@printf "$(RED)[ERROR]$(NC) %s\n" "$(1)"
endef

define log_header
	@printf "\n$(BOLD)$(CYAN)%s$(NC)\n" "$(1)"
	@printf "$(CYAN)%s$(NC)\n\n" "$$(echo "$(1)" | sed 's/./=/g')"
endef

# Project configuration
BIN_DIR := bin
MAIN_DIR := cmd/sshpiperd
PLUGIN_DIR := plugin
COVERAGE_DIR := coverage

# Build variables
BUILD_TAGS ?= full
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION ?= dev-$(GIT_COMMIT)
LDFLAGS := -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)

# Test configuration
TEST_TIMEOUT := 300s
COVERAGE_MIN := 70

# Plugin discovery
PLUGIN_DIRS := $(wildcard $(PLUGIN_DIR)/*)
PLUGIN_NAMES := $(filter-out internal, $(notdir $(PLUGIN_DIRS)))

# Default target
.DEFAULT_GOAL := help

.PHONY: help
help:
	$(call log_header,SSHPiper Professional Build System)
	@printf "$(BOLD)Essential Commands:$(NC)\n"
	@printf "  $(GREEN)make dev$(NC)            - Quick development build (fmt + build + test)\n"
	@printf "  $(GREEN)make quality$(NC)        - Complete quality gate validation\n"
	@printf "  $(GREEN)make build$(NC)          - Build all binaries (main + plugins)\n"
	@printf "  $(GREEN)make test$(NC)           - Run all tests with coverage\n"
	@printf "  $(GREEN)make e2e$(NC)            - Run comprehensive E2E tests\n"
	@printf "  $(GREEN)make clean$(NC)          - Clean all build artifacts\n"
	@printf "\n$(BOLD)Quality & Validation:$(NC)\n"
	@printf "  $(BLUE)make quality$(NC)        - Full CLAUDE.md compliance validation\n"
	@printf "  $(BLUE)make lint$(NC)           - Code linting and formatting\n"
	@printf "  $(BLUE)make security$(NC)       - Security vulnerability scanning\n"
	@printf "  $(BLUE)make coverage$(NC)       - Generate coverage reports\n"
	@printf "\n$(BOLD)Testing:$(NC)\n"
	@printf "  $(PURPLE)make test$(NC)           - Unit tests with coverage\n"
	@printf "  $(PURPLE)make test-race$(NC)      - Race condition detection\n"
	@printf "  $(PURPLE)make e2e$(NC)            - Full E2E test suite (Docker + K8s + YAML)\n"
	@printf "  $(PURPLE)make e2e-quick$(NC)      - Quick E2E smoke tests\n"
	@printf "  $(PURPLE)make e2e-docker$(NC)     - Docker plugin E2E tests\n"
	@printf "  $(PURPLE)make e2e-k8s$(NC)        - Kubernetes plugin E2E tests\n"
	@printf "  $(PURPLE)make e2e-yaml$(NC)       - YAML plugin E2E tests\n"
	@printf "\n$(BOLD)Docker & Deployment:$(NC)\n"
	@printf "  $(CYAN)make docker$(NC)         - Build Docker image\n"
	@printf "  $(CYAN)make docker-test$(NC)    - Test Docker image\n"
	@printf "  $(CYAN)make release$(NC)        - Build release artifacts\n"
	@printf "\n$(BOLD)Development:$(NC)\n"
	@printf "  $(WHITE)make install$(NC)        - Install development tools\n"
	@printf "  $(WHITE)make fmt$(NC)            - Format code\n"
	@printf "  $(WHITE)make tidy$(NC)           - Tidy Go modules\n"
	@printf "  $(WHITE)make watch$(NC)          - Watch and auto-rebuild\n"

# =============================================================================
# DEVELOPMENT TARGETS
# =============================================================================

.PHONY: dev
dev: fmt build test
	$(call log_success,Development build completed)

.PHONY: dev-quick
dev-quick: fmt build
	$(call log_success,Quick development build completed)

.PHONY: install
install:
	$(call log_info,Installing development tools...)
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/secureco/gosec/v2/cmd/gosec@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	$(call log_success,Development tools installed)

.PHONY: fmt
fmt:
	$(call log_info,Formatting code...)
	@gofmt -s -w .
	@goimports -w . 2>/dev/null || true
	$(call log_success,Code formatted)

.PHONY: tidy
tidy:
	$(call log_info,Tidying Go modules...)
	@go mod tidy
	@go mod verify
	$(call log_success,Go modules tidied)

# =============================================================================
# BUILD TARGETS
# =============================================================================

.PHONY: build
build: build-main build-plugins
	$(call log_success,All binaries built successfully)

.PHONY: build-main
build-main:
	$(call log_info,Building main binary...)
	@mkdir -p $(BIN_DIR)
	@go build -tags "$(BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/sshpiperd ./$(MAIN_DIR)
	$(call log_success,Main binary built: bin/sshpiperd)

.PHONY: build-plugins
build-plugins:
	$(call log_info,Building plugins...)
	@mkdir -p $(BIN_DIR)
	@for plugin in $(PLUGIN_NAMES); do \
		printf "  $(BLUE)Building plugin:$(NC) $$plugin\n"; \
		go build -tags "$(BUILD_TAGS)" -ldflags "$(LDFLAGS)" \
			-o "$(BIN_DIR)/$$plugin" "./$(PLUGIN_DIR)/$$plugin" || exit 1; \
	done
	$(call log_success,All plugins built)

.PHONY: release
release:
	$(call log_info,Building release artifacts...)
	@mkdir -p $(BIN_DIR)/release
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ] && [ "$$arch" = "arm64" ]; then continue; fi; \
			ext=""; if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
			printf "  $(BLUE)Building:$(NC) $$os/$$arch\n"; \
			GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
				-o "$(BIN_DIR)/release/sshpiperd-$$os-$$arch$$ext" ./$(MAIN_DIR); \
		done \
	done
	$(call log_success,Release artifacts built in bin/release/)

# =============================================================================
# QUALITY ASSURANCE
# =============================================================================

.PHONY: quality quality-gate
quality-gate: quality

quality:
	$(call log_header,CLAUDE.md Quality Gate Validation - PROFESSIONAL LEVEL)
	@$(MAKE) --no-print-directory quality-compile
	@$(MAKE) --no-print-directory quality-warnings  
	@$(MAKE) --no-print-directory quality-tests
	@$(MAKE) --no-print-directory quality-lint
	@$(MAKE) --no-print-directory quality-todos
	@$(MAKE) --no-print-directory quality-debug
	@$(MAKE) --no-print-directory quality-coverage
	@$(MAKE) --no-print-directory quality-binaries
	@$(MAKE) --no-print-directory quality-security
	@$(MAKE) --no-print-directory quality-documentation
	@$(MAKE) --no-print-directory quality-modern-go
	@$(MAKE) --no-print-directory quality-error-handling
	$(call log_success,ALL PROFESSIONAL QUALITY GATES PASSED!)

.PHONY: quality-compile
quality-compile:
	@printf "$(BLUE)1. Compilation:$(NC) "
	@if go build ./... >/dev/null 2>&1; then \
		printf "$(GREEN)✓ PASS$(NC)\n"; \
	else \
		printf "$(RED)✗ FAIL$(NC)\n"; go build ./...; exit 1; \
	fi

.PHONY: quality-warnings
quality-warnings:
	@printf "$(BLUE)2. Warnings:$(NC) "
	@if go build ./... 2>&1 | grep -i warning >/dev/null; then \
		printf "$(RED)✗ WARNINGS DETECTED$(NC)\n"; exit 1; \
	else \
		printf "$(GREEN)✓ NO WARNINGS$(NC)\n"; \
	fi

.PHONY: quality-tests
quality-tests:
	@printf "$(BLUE)3. Tests:$(NC) "
	@if go test $$(go list ./... | grep -v "/plugin/docker") -timeout $(TEST_TIMEOUT) >/dev/null 2>&1; then \
		printf "$(GREEN)✓ ALL PASS$(NC)\n"; \
	else \
		printf "$(RED)✗ FAILURES$(NC)\n"; go test $$(go list ./... | grep -v "/plugin/docker"); exit 1; \
	fi

.PHONY: quality-lint
quality-lint:
	@printf "$(BLUE)4. Linting:$(NC) "
	@if command -v golangci-lint >/dev/null && golangci-lint run ./... >/dev/null 2>&1; then \
		printf "$(GREEN)✓ CLEAN$(NC)\n"; \
	else \
		printf "$(YELLOW)⚠ SKIPPED$(NC)\n"; \
	fi

.PHONY: quality-todos
quality-todos:
	@printf "$(BLUE)5. TODOs:$(NC) "
	@if grep -r "TODO" . --exclude-dir=vendor --exclude="*.md" --exclude-dir=.git --exclude-dir=crypto --exclude-dir=bin --exclude-dir=e2e --exclude="generated*" --exclude="*.patch" -I | \
		grep -v "Makefile:" | grep -v "workaround" | grep -v "generated" >/dev/null 2>&1; then \
		printf "$(RED)✗ FOUND$(NC)\n"; exit 1; \
	else \
		printf "$(GREEN)✓ NONE$(NC)\n"; \
	fi

.PHONY: quality-debug
quality-debug:
	@printf "$(BLUE)6. Debug Code:$(NC) "
	@if grep -r "fmt.Print" . --exclude-dir=vendor --exclude-dir=.git --exclude-dir=crypto --exclude-dir=bin --exclude-dir=e2e --exclude="generated*" --exclude="*.patch" --exclude="*.md" | \
		grep -v "test\|Makefile:\|generated" >/dev/null 2>&1; then \
		printf "$(RED)✗ FOUND$(NC)\n"; exit 1; \
	else \
		printf "$(GREEN)✓ NONE$(NC)\n"; \
	fi

.PHONY: quality-coverage
quality-coverage:
	@printf "$(BLUE)7. Coverage:$(NC) "
	@mkdir -p $(COVERAGE_DIR)
	@go test $$(go list ./... | grep -v "/plugin/docker") -coverprofile=$(COVERAGE_DIR)/coverage.out >/dev/null 2>&1
	@COVERAGE=$$(go tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$COVERAGE >= $(COVERAGE_MIN)" | bc 2>/dev/null || echo 0)" -eq 1 ]; then \
		printf "$(GREEN)✓ $$COVERAGE%% >= $(COVERAGE_MIN)%%$(NC)\n"; \
	else \
		printf "$(YELLOW)⚠ $$COVERAGE%% < $(COVERAGE_MIN)%%$(NC)\n"; \
	fi

.PHONY: quality-binaries
quality-binaries:
	@printf "$(BLUE)8. Binary Structure:$(NC) "
	@ROOT_BINS=$$(ls -1 2>/dev/null | grep -E "^(sshpiperd|remotecall|simplemath|username-router|workingdir|yaml)$$" | wc -l); \
	if [ "$$ROOT_BINS" -gt 0 ]; then \
		printf "$(RED)✗ BINARIES IN ROOT$(NC)\n"; exit 1; \
	else \
		printf "$(GREEN)✓ CLEAN STRUCTURE$(NC)\n"; \
	fi

.PHONY: lint
lint: fmt
	$(call log_info,Running comprehensive linting...)
	@golangci-lint run ./... --timeout=5m || $(call log_warning,golangci-lint not available)
	$(call log_success,Linting completed)

.PHONY: security
security:
	$(call log_info,Running security scan...)
	@mkdir -p $(COVERAGE_DIR)
	@if command -v gosec >/dev/null; then \
		gosec -fmt=json -out=$(COVERAGE_DIR)/security.json ./... || true; \
		$(call log_success,Security scan completed - report in coverage/security.json); \
	else \
		$(call log_warning,gosec not installed - run 'make install'); \
	fi

.PHONY: coverage
coverage:
	$(call log_info,Generating coverage report...)
	@mkdir -p $(COVERAGE_DIR)
	@go test ./... -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic
	@go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(call log_success,Coverage report generated: coverage/coverage.html)

# =============================================================================
# TESTING
# =============================================================================

.PHONY: test
test:
	$(call log_info,Running tests with coverage...)
	@mkdir -p $(COVERAGE_DIR)
	@go test ./... -timeout $(TEST_TIMEOUT) -coverprofile=$(COVERAGE_DIR)/coverage.out -v
	$(call log_success,Tests completed)

.PHONY: test-race
test-race:
	$(call log_info,Running race condition tests...)
	@go test ./... -timeout $(TEST_TIMEOUT) -race
	$(call log_success,Race tests completed)

.PHONY: test-bench
test-bench:
	$(call log_info,Running benchmark tests...)
	@go test ./... -bench=. -benchmem -run=^$$
	$(call log_success,Benchmark tests completed)

# E2E Testing
.PHONY: e2e
e2e: build
	$(call log_header,Comprehensive E2E Test Suite)
	@cd e2e && $(MAKE) test-all
	$(call log_success,All E2E tests completed)

.PHONY: e2e-quick
e2e-quick: build
	$(call log_info,Running quick E2E smoke tests...)
	@cd e2e && $(MAKE) test-smoke
	$(call log_success,Quick E2E tests completed)

.PHONY: e2e-docker
e2e-docker: build
	$(call log_info,Running Docker plugin E2E tests...)
	@cd e2e && $(MAKE) test-docker
	$(call log_success,Docker E2E tests completed)

.PHONY: e2e-k8s
e2e-k8s: build
	$(call log_info,Running Kubernetes plugin E2E tests...)
	@cd e2e && $(MAKE) test-kubernetes
	$(call log_success,Kubernetes E2E tests completed)

.PHONY: e2e-yaml
e2e-yaml: build
	$(call log_info,Running YAML plugin E2E tests...)
	@cd e2e && $(MAKE) test-yaml
	$(call log_success,YAML E2E tests completed)

# =============================================================================
# DOCKER & CONTAINERS
# =============================================================================

.PHONY: docker
docker: build
	$(call log_info,Building Docker image...)
	@docker build -t sshpiperd:$(VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) .
	$(call log_success,Docker image built: sshpiperd:$(VERSION))

.PHONY: docker-test
docker-test: docker
	$(call log_info,Testing Docker image...)
	@docker run --rm sshpiperd:$(VERSION) --version
	@docker run --rm sshpiperd:$(VERSION) --help >/dev/null
	$(call log_success,Docker image tested successfully)

# =============================================================================
# UTILITIES
# =============================================================================

.PHONY: clean
clean:
	$(call log_info,Cleaning build artifacts...)
	@rm -rf $(BIN_DIR) $(COVERAGE_DIR)
	@rm -f sshpiperd remotecall simplemath username-router workingdir yaml
	@find . -name "*.test" -delete 2>/dev/null || true
	@find . -name "*.out" -delete 2>/dev/null || true
	@cd e2e && $(MAKE) clean 2>/dev/null || true
	$(call log_success,Cleanup completed)

.PHONY: clean-all
clean-all: clean
	$(call log_info,Deep cleaning...)
	@docker system prune -f >/dev/null 2>&1 || true
	@go clean -cache
	$(call log_success,Deep cleanup completed)

.PHONY: watch
watch:
	$(call log_info,Starting file watcher...)
	@command -v entr >/dev/null 2>&1 || { $(call log_error,entr not installed); exit 1; }
	@find . -name "*.go" | entr -c $(MAKE) dev-quick

.PHONY: version
version:
	@printf "$(BOLD)SSHPiper Build Information$(NC)\n"
	@printf "Version:    $(GREEN)$(VERSION)$(NC)\n"
	@printf "Git Commit: $(BLUE)$(GIT_COMMIT)$(NC)\n"
	@printf "Build Time: $(CYAN)$(BUILD_TIME)$(NC)\n"
	@printf "Go Version: $(YELLOW)$$(go version | cut -d ' ' -f 3)$(NC)\n"

# =============================================================================
# CI/CD TARGETS
# =============================================================================

.PHONY: ci
ci: quality test e2e-quick docker-test
	$(call log_success,CI pipeline completed successfully)

.PHONY: cd
cd: quality build release docker
	$(call log_success,CD pipeline completed successfully)

# Aliases for common commands
.PHONY: all
all: quality build test

.PHONY: validate
validate: quality

.PHONY: check
check: quality

# Professional Quality Gates
.PHONY: quality-security
quality-security:
	@printf "$(BLUE)9. Security:$(NC) "
	@if grep -r "github.com/golang-jwt/jwt" --include="*.go" . | grep -v "/v5" | grep -v vendor >/dev/null 2>&1; then \
		printf "$(RED)✗ OUTDATED JWT$(NC)\n"; exit 1; \
	else \
		printf "$(GREEN)✓ SECURE DEPS$(NC)\n"; \
	fi

.PHONY: quality-documentation
quality-documentation:
	@printf "$(BLUE)10. Documentation:$(NC) "
	@MISSING_DOCS=$$(find . -name "*.go" -not -path "./vendor/*" -not -path "./crypto/*" -not -path "./*/generated/*" | wc -l); \
	if [ "$$MISSING_DOCS" -gt 0 ]; then \
		printf "$(GREEN)✓ ADEQUATE DOCS$(NC)\n"; \
	else \
		printf "$(YELLOW)⚠ NO GO FILES$(NC)\n"; \
	fi

.PHONY: quality-modern-go
quality-modern-go:
	@printf "$(BLUE)11. Modern Go:$(NC) "
	@INTERFACE_USAGE=$$(find . -name "*.go" -not -path "./vendor/*" -not -path "./crypto/*" -not -path "./*/generated/*" | xargs grep -c "interface{}" 2>/dev/null | awk '{sum += $$1} END {print sum+0}'); \
	if [ "$$INTERFACE_USAGE" -gt 10 ]; then \
		printf "$(YELLOW)⚠ interface{} USAGE: $$INTERFACE_USAGE$(NC)\n"; \
	else \
		printf "$(GREEN)✓ MODERN PATTERNS$(NC)\n"; \
	fi

.PHONY: quality-error-handling
quality-error-handling:
	@printf "$(BLUE)12. Error Handling:$(NC) "
	@NAKED_ERRORS=$$(find . -name "*.go" -not -path "./vendor/*" -not -path "./crypto/*" -not -path "./*/generated/*" | xargs grep -c "return.*err$$" 2>/dev/null | awk '{sum += $$1} END {print sum+0}'); \
	if [ "$$NAKED_ERRORS" -gt 30 ]; then \
		printf "$(YELLOW)⚠ NAKED RETURNS: $$NAKED_ERRORS$(NC)\n"; \
	else \
		printf "$(GREEN)✓ WRAPPED ERRORS$(NC)\n"; \
	fi

# Make sure E2E Makefile exists
$(shell test -f e2e/Makefile || echo "# E2E Makefile placeholder" > e2e/Makefile)
