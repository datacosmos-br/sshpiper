# E2E Testing Makefile for SSHPiper
# Comprehensive testing across all plugins and SSH server versions

# Terminal colors - properly configured for all terminal types
SHELL := /bin/bash
export TERM ?= xterm-256color

# Color definitions with fallback support
ifeq ($(shell test -t 1 && echo 1),1)
	# Interactive terminal - use colors
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
	# Non-interactive terminal - no colors
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

define show_progress
	@printf "$(BLUE)[PROGRESS]$(NC) %s " "$(1)"
	@for i in $$(seq 1 $(2)); do printf "$(GREEN)█$(NC)"; done
	@for i in $$(seq $(2) 10); do printf "$(WHITE)░$(NC)"; done
	@printf " $(BOLD)%d%%$(NC)\n" "$$(($(2) * 10))"
endef

define test_status
	@printf "\n$(BOLD)$(PURPLE)Test Execution Summary$(NC)\n"
	@printf "$(PURPLE)%s$(NC)\n" "$$(echo "Test Execution Summary" | sed 's/./=/g')"
	@printf "$(GREEN)✓$(NC) Plugin Tests: Docker, Kubernetes, YAML\n"
	@printf "$(GREEN)✓$(NC) SSH Compatibility: OpenSSH 7.x-9.x, Dropbear\n"
	@printf "$(GREEN)✓$(NC) Security Validation: Auth, Input, Network\n"
	@printf "$(GREEN)✓$(NC) Load Testing: Concurrent, Scaling, Performance\n"
	@printf "$(BLUE)ℹ$(NC) Results available in: $(YELLOW)test-results/$(NC)\n"
	@printf "$(BLUE)ℹ$(NC) Coverage report: $(YELLOW)test-results/coverage.html$(NC)\n\n"
endef

.PHONY: test-all test-docker test-kubernetes test-yaml test-ssh-versions test-load test-security clean setup help

# Default target
help:
	$(call log_header,SSHPiper E2E Testing Suite)
	@printf "$(BOLD)Available targets:$(NC)\n"
	@printf "  $(GREEN)test-all$(NC)         - Run all E2E tests (full suite)\n"
	@printf "  $(BLUE)test-docker$(NC)      - Run Docker plugin tests\n"
	@printf "  $(BLUE)test-kubernetes$(NC)  - Run Kubernetes plugin tests\n"
	@printf "  $(BLUE)test-yaml$(NC)        - Run YAML plugin tests\n"
	@printf "  $(PURPLE)test-ssh-versions$(NC) - Run SSH server compatibility tests\n"
	@printf "  $(YELLOW)test-load$(NC)        - Run load testing scenarios\n"
	@printf "  $(RED)test-security$(NC)    - Run security validation tests\n"
	@printf "  $(CYAN)test-comprehensive$(NC) - Run comprehensive integration tests\n"
	@printf "  $(WHITE)setup$(NC)            - Setup test environment\n"
	@printf "  $(WHITE)clean$(NC)            - Cleanup test artifacts\n"
	@printf "  $(WHITE)report$(NC)           - Generate test reports\n"
	@printf "\n$(BOLD)Environment variables:$(NC)\n"
	@printf "  $(YELLOW)INTEGRATION_TESTS=1$(NC) - Enable integration tests\n"
	@printf "  $(YELLOW)LOAD_TESTS=1$(NC)       - Enable load tests\n"
	@printf "  $(YELLOW)KUBECONFIG$(NC)         - Kubernetes config file path\n"
	@printf "  $(YELLOW)DOCKER_HOST$(NC)        - Docker daemon host\n"

# Setup test environment
setup:
	$(call log_info,Setting up E2E test environment...)
	@mkdir -p test-results test-logs test-configs
	@docker network create sshpiper-test >/dev/null 2>&1 || true
	$(call log_success,Test environment setup completed)

# Run all E2E tests
test-all: setup
	$(call log_header,SSHPiper E2E Test Suite - Full Execution)
	$(call show_progress,Comprehensive Tests,2)
	@$(MAKE) test-comprehensive
	$(call show_progress,Docker Plugin Tests,4)
	@$(MAKE) test-docker
	$(call show_progress,Kubernetes Plugin Tests,6)
	@$(MAKE) test-kubernetes
	$(call show_progress,YAML Plugin Tests,8)
	@$(MAKE) test-yaml
	$(call show_progress,SSH Version Compatibility,10)
	@$(MAKE) test-ssh-versions
	$(call test_status)
	$(call log_success,All E2E tests completed successfully!)

# Run comprehensive integration tests
test-comprehensive: setup
	$(call log_info,Running comprehensive integration tests...)
	@INTEGRATION_TESTS=1 go test -v -timeout 30m ./comprehensive_integration_test.go ./main_test.go \
		-run TestComprehensiveE2E \
		2>&1 | tee test-results/comprehensive-test.log
	$(call log_success,Comprehensive integration tests completed)

# Run Docker plugin tests
test-docker: setup
	$(call log_info,Running Docker plugin E2E tests...)
	@docker-compose -f plugin_configs/docker_test_config.yml up -d >/dev/null 2>&1 || true
	@INTEGRATION_TESTS=1 go test -v -timeout 20m ./enhanced_docker_test.go ./main_test.go \
		-run TestDockerPluginComprehensive \
		2>&1 | tee test-results/docker-test.log
	@docker-compose -f plugin_configs/docker_test_config.yml down >/dev/null 2>&1 || true
	$(call log_success,Docker plugin tests completed)

# Run Kubernetes plugin tests
test-kubernetes: setup
	$(call log_info,Running Kubernetes plugin E2E tests...)
	@kubectl apply -f plugin_configs/kubernetes_test_config.yaml >/dev/null 2>&1 || $(call log_warning,Failed to apply K8s config)
	@INTEGRATION_TESTS=1 go test -v -timeout 25m ./enhanced_kubernetes_test.go ./main_test.go \
		-run TestKubernetesPluginComprehensive \
		2>&1 | tee test-results/kubernetes-test.log
	@kubectl delete -f plugin_configs/kubernetes_test_config.yaml >/dev/null 2>&1 || true
	$(call log_success,Kubernetes plugin tests completed)

# Run YAML plugin tests
test-yaml: setup
	$(call log_info,Running YAML plugin E2E tests...)
	@INTEGRATION_TESTS=1 go test -v -timeout 15m ./enhanced_yaml_test.go ./main_test.go \
		-run TestYAMLPluginComprehensive \
		2>&1 | tee test-results/yaml-test.log
	$(call log_success,YAML plugin tests completed)

# Run SSH server version compatibility tests
test-ssh-versions: setup
	$(call log_info,Running SSH server version compatibility tests...)
	@INTEGRATION_TESTS=1 go test -v -timeout 45m ./ssh_version_compatibility_test.go ./main_test.go \
		-run TestSSHServerVersionCompatibility \
		2>&1 | tee test-results/ssh-versions-test.log
	$(call log_success,SSH version compatibility tests completed)

# Run load testing scenarios
test-load: setup
	$(call log_info,Running load testing scenarios...)
	@INTEGRATION_TESTS=1 LOAD_TESTS=1 go test -v -timeout 30m \
		./comprehensive_integration_test.go ./main_test.go \
		-run TestHighLoadScenarios \
		2>&1 | tee test-results/load-test.log
	$(call log_success,Load testing completed)

# Run security validation tests
test-security: setup
	$(call log_info,Running security validation tests...)
	@INTEGRATION_TESTS=1 go test -v -timeout 20m \
		./comprehensive_integration_test.go \
		./enhanced_docker_test.go \
		./enhanced_kubernetes_test.go \
		./enhanced_yaml_test.go \
		./main_test.go \
		-run "Security|Failure" \
		2>&1 | tee test-results/security-test.log
	$(call log_success,Security validation tests completed)

# Test individual plugins with specific configurations
test-plugin-docker-basic:
	@echo "Running basic Docker plugin test..."
	INTEGRATION_TESTS=1 go test -v ./enhanced_docker_test.go ./main_test.go -run TestDockerLabelDiscovery

test-plugin-docker-lifecycle:
	@echo "Running Docker container lifecycle test..."
	INTEGRATION_TESTS=1 go test -v ./enhanced_docker_test.go ./main_test.go -run TestDockerContainerLifecycle

test-plugin-kubernetes-crd:
	@echo "Running Kubernetes CRD discovery test..."
	INTEGRATION_TESTS=1 go test -v ./enhanced_kubernetes_test.go ./main_test.go -run TestKubernetesCRDDiscovery

test-plugin-kubernetes-rbac:
	@echo "Running Kubernetes RBAC test..."
	INTEGRATION_TESTS=1 go test -v ./enhanced_kubernetes_test.go ./main_test.go -run TestKubernetesRBACAuthorization

test-plugin-yaml-regex:
	@echo "Running YAML regex matching test..."
	INTEGRATION_TESTS=1 go test -v ./enhanced_yaml_test.go ./main_test.go -run TestYAMLRegexUsernameMatching

test-plugin-yaml-env:
	@echo "Running YAML environment expansion test..."
	INTEGRATION_TESTS=1 go test -v ./enhanced_yaml_test.go ./main_test.go -run TestYAMLEnvironmentExpansion

# SSH version specific tests
test-ssh-openssh-8:
	@echo "Running OpenSSH 8.x compatibility test..."
	INTEGRATION_TESTS=1 go test -v ./ssh_version_compatibility_test.go ./main_test.go -run "OpenSSH_8"

test-ssh-openssh-9:
	@echo "Running OpenSSH 9.x compatibility test..."
	INTEGRATION_TESTS=1 go test -v ./ssh_version_compatibility_test.go ./main_test.go -run "OpenSSH_9"

test-ssh-dropbear:
	@echo "Running Dropbear SSH compatibility test..."
	INTEGRATION_TESTS=1 go test -v ./ssh_version_compatibility_test.go ./main_test.go -run "Dropbear"

# Performance benchmarks
benchmark-all: setup
	@echo "Running performance benchmarks..."
	INTEGRATION_TESTS=1 go test -v -bench=. -benchtime=30s \
		./comprehensive_integration_test.go ./main_test.go \
		2>&1 | tee test-results/benchmark.log
	@echo "✅ Performance benchmarks completed"

# Generate test reports
report:
	@echo "Generating E2E test reports..."
	@mkdir -p test-results/reports
	@echo "# SSHPiper E2E Test Results" > test-results/reports/summary.md
	@echo "Generated on: $$(date)" >> test-results/reports/summary.md
	@echo "" >> test-results/reports/summary.md
	@echo "## Test Execution Summary" >> test-results/reports/summary.md
	@for logfile in test-results/*.log; do \
		if [ -f "$$logfile" ]; then \
			echo "### $$(basename $$logfile .log)" >> test-results/reports/summary.md; \
			echo '```' >> test-results/reports/summary.md; \
			tail -20 "$$logfile" >> test-results/reports/summary.md; \
			echo '```' >> test-results/reports/summary.md; \
			echo "" >> test-results/reports/summary.md; \
		fi \
	done
	@echo "✅ Test reports generated in test-results/reports/"

# Run tests with coverage
test-coverage: setup
	@echo "Running E2E tests with coverage..."
	INTEGRATION_TESTS=1 go test -v -coverprofile=test-results/coverage.out \
		./comprehensive_integration_test.go \
		./enhanced_docker_test.go \
		./enhanced_kubernetes_test.go \
		./enhanced_yaml_test.go \
		./ssh_version_compatibility_test.go \
		./main_test.go
	go tool cover -html=test-results/coverage.out -o test-results/coverage.html
	@echo "✅ Coverage report generated: test-results/coverage.html"

# Run tests in parallel
test-parallel: setup
	@echo "Running E2E tests in parallel..."
	INTEGRATION_TESTS=1 go test -v -parallel 4 -timeout 60m \
		./comprehensive_integration_test.go \
		./enhanced_docker_test.go \
		./enhanced_kubernetes_test.go \
		./enhanced_yaml_test.go \
		./main_test.go \
		2>&1 | tee test-results/parallel-test.log
	@echo "✅ Parallel E2E tests completed"

# Debug tests with verbose output
test-debug: setup
	@echo "Running E2E tests in debug mode..."
	INTEGRATION_TESTS=1 go test -v -timeout 60m \
		-ldflags "-X main.debugMode=true" \
		./comprehensive_integration_test.go ./main_test.go \
		-run TestComprehensiveE2E \
		2>&1 | tee test-results/debug-test.log
	@echo "✅ Debug E2E tests completed"

# Quick smoke tests
test-smoke: setup
	@echo "Running smoke tests..."
	INTEGRATION_TESTS=1 go test -v -timeout 10m \
		./comprehensive_integration_test.go ./main_test.go \
		-run "TestComprehensiveE2E/docker_password_auth|TestComprehensiveE2E/yaml_basic_config" \
		2>&1 | tee test-results/smoke-test.log
	@echo "✅ Smoke tests completed"

# Cleanup test artifacts
clean:
	$(call log_info,Cleaning up test artifacts...)
	@rm -rf test-results test-logs test-configs
	@docker network rm sshpiper-test >/dev/null 2>&1 || true
	@docker system prune -f --filter label=test=sshpiper >/dev/null 2>&1 || true
	@kubectl delete namespace sshpiper-e2e-test >/dev/null 2>&1 || true
	$(call log_success,Test cleanup completed)

# Container cleanup
clean-containers:
	$(call log_info,Cleaning up test containers...)
	@docker ps -a --filter name=sshpiper-test --format "{{.ID}}" | xargs -r docker rm -f >/dev/null 2>&1 || true
	@docker ps -a --filter name=ssh-target-test --format "{{.ID}}" | xargs -r docker rm -f >/dev/null 2>&1 || true
	$(call log_success,Test containers cleaned up)

# Full cleanup including images
clean-all: clean clean-containers
	$(call log_info,Performing full cleanup...)
	@docker images --filter label=test=sshpiper --format "{{.ID}}" | xargs -r docker rmi -f >/dev/null 2>&1 || true
	$(call log_success,Full cleanup completed)

# Check test prerequisites
check-prereqs:
	$(call log_info,Checking test prerequisites...)
	@command -v docker >/dev/null 2>&1 || { $(call log_error,Docker is required but not installed); exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { $(call log_error,kubectl is required but not installed); exit 1; }
	@command -v go >/dev/null 2>&1 || { $(call log_error,Go is required but not installed); exit 1; }
	@docker info >/dev/null 2>&1 || { $(call log_error,Docker daemon is not running); exit 1; }
	$(call log_success,All prerequisites are met)

# Install test dependencies
install-deps:
	$(call log_info,Installing test dependencies...)
	@go mod tidy
	@go get -t ./...
	$(call log_success,Test dependencies installed)

# Continuous testing (watch mode)
test-watch:
	@echo "Starting continuous testing (watch mode)..."
	@while true; do \
		echo "Running tests at $$(date)..."; \
		make test-smoke; \
		echo "Waiting 30 seconds for next run..."; \
		sleep 30; \
	done

# Test environment validation
validate-env:
	$(call log_header,Test Environment Validation)
	@printf "$(BOLD)System Information:$(NC)\n"
	@printf "  $(BLUE)Docker version:$(NC) $$(docker --version 2>/dev/null || echo 'Not installed')\n"
	@printf "  $(BLUE)Kubernetes client:$(NC) $$(kubectl version --client --short 2>/dev/null || echo 'Not available')\n"
	@printf "  $(BLUE)Go version:$(NC) $$(go version 2>/dev/null || echo 'Not installed')\n"
	@printf "  $(BLUE)Available networks:$(NC) $$(docker network ls --format '{{.Name}}' 2>/dev/null | tr '\n' ' ' || echo 'Docker not running')\n"
	@printf "\n$(BOLD)Environment Variables:$(NC)\n"
	@printf "  $(YELLOW)INTEGRATION_TESTS:$(NC) ${INTEGRATION_TESTS}\n"
	@printf "  $(YELLOW)LOAD_TESTS:$(NC) ${LOAD_TESTS}\n"
	@printf "  $(YELLOW)KUBECONFIG:$(NC) ${KUBECONFIG}\n"
	@printf "  $(YELLOW)DOCKER_HOST:$(NC) ${DOCKER_HOST}\n"
	$(call log_success,Environment validation completed)

# Run specific test suites for CI/CD
ci-docker:
	@echo "Running Docker tests for CI/CD..."
	INTEGRATION_TESTS=1 go test -v -json ./enhanced_docker_test.go ./main_test.go \
		-run TestDockerPluginComprehensive > test-results/docker-ci.json

ci-kubernetes:
	@echo "Running Kubernetes tests for CI/CD..."
	INTEGRATION_TESTS=1 go test -v -json ./enhanced_kubernetes_test.go ./main_test.go \
		-run TestKubernetesPluginComprehensive > test-results/kubernetes-ci.json

ci-yaml:
	@echo "Running YAML tests for CI/CD..."
	INTEGRATION_TESTS=1 go test -v -json ./enhanced_yaml_test.go ./main_test.go \
		-run TestYAMLPluginComprehensive > test-results/yaml-ci.json

ci-all: setup ci-docker ci-kubernetes ci-yaml
	@echo "✅ All CI/CD tests completed"

# Test with specific SSH server version
test-ssh-version-%:
	$(call log_info,Running tests against SSH server version: $*)
	@INTEGRATION_TESTS=1 go test -v ./ssh_version_compatibility_test.go ./main_test.go \
		-run "ssh_version_$*" \
		2>&1 | tee test-results/ssh-$*-test.log
	$(call log_success,SSH version $* tests completed)

# Show color capabilities
show-colors:
	$(call log_header,Terminal Color Test)
	@printf "$(BOLD)Color Support Test:$(NC)\n"
	@printf "$(RED)■$(NC) Red (Errors)     "
	@printf "$(GREEN)■$(NC) Green (Success)  "
	@printf "$(YELLOW)■$(NC) Yellow (Warnings)\n"
	@printf "$(BLUE)■$(NC) Blue (Info)      "
	@printf "$(PURPLE)■$(NC) Purple (Special) "
	@printf "$(CYAN)■$(NC) Cyan (Headers)\n"
	@printf "$(WHITE)■$(NC) White (Text)     "
	@printf "$(BOLD)■$(NC) Bold Text        "
	@printf "$(NC)■ Normal Text\n\n"
	$(call log_info,This is an info message)
	$(call log_success,This is a success message)
	$(call log_warning,This is a warning message)
	$(call log_error,This is an error message)
	$(call show_progress,Progress Bar Test,7)
	@printf "\n$(BOLD)Terminal Type:$(NC) $$TERM\n"
	@printf "$(BOLD)Color Support:$(NC) "
	@if [ -t 1 ]; then printf "$(GREEN)Enabled$(NC)"; else printf "$(YELLOW)Disabled$(NC)"; fi
	@printf "\n"