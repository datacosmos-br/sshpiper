# Directories
BIN_DIR := bin
MAIN_DIR := cmd/sshpiperd
PLUGIN_DIR := plugin

# Automatically find all plugin directories (each must have a main.go),
# excluding the "internal" plugin.
PLUGIN_DIRS := $(wildcard $(PLUGIN_DIR)/*)
PLUGIN_NAMES := $(filter-out internal, $(notdir $(PLUGIN_DIRS)))

# Plugin binaries will be built for each plugin in PLUGIN_NAMES.
PLUGIN_BINS := $(patsubst %, $(BIN_DIR)/sshpiperd-%, $(PLUGIN_NAMES))

# Main binary output
MAIN_BIN := $(BIN_DIR)/sshpiperd

# Build variables
BUILD_TAGS ?= full

# Docker image variables
IMAGE ?= gru.ocir.io/grq1iurfepyg/sshpiperd
TAG ?= latest

.PHONY: all vendor fmt vet lint check codegen codegen-k8s gen-main build-main build-plugins build docker-local docker-build-push test clean e2e e2e-all kind-up kind-down kind-status kind-load prereqs e2e-all-full kind-local build-e2e-plugins

# Default target: run vendor, check, codegen, build and docker targets
all: vendor check codegen build docker-local docker-build-push

# Vendor dependencies
vendor:
	@echo "Vendoring dependencies..."
	go mod vendor

# Code formatting
fmt:
	@echo "Running go fmt..."
	go fmt ./...

# Go vet for static analysis
vet:
	@echo "Running go vet..."
	go vet ./...

# Lint using revive (certifique-se de ter o revive instalado e o arquivo revive.toml na raiz)
lint: fmt vet
	@echo "Running revive linting..."
	@if [ -f revive.toml ]; then \
	  revive -config revive.toml ./...; \
	else \
	  echo "revive.toml not found, running revive with default configuration"; \
	  revive ./...; \
	fi

# Combined check target (fmt, vet, lint)
check: fmt vet lint

# Update Kubernetes code generation (o script update-codegen.sh deve estar executável)
codegen-k8s:
	@echo "Running Kubernetes code generation..."
	sh $(PLUGIN_DIR)/kubernetes/update-codegen.sh

# Code generation for main program (se necessário, utiliza go generate)
gen-main:
	@echo "Running code generation for main program..."
	cd $(MAIN_DIR) && go generate ./...

# Combined code generation target
codegen: codegen-k8s gen-main

# Build main program
build-main:
	@echo "Building main program with tags $(BUILD_TAGS)..."
	@mkdir -p $(BIN_DIR)
	cd $(MAIN_DIR) && go build -tags "$(BUILD_TAGS)" -o ../../$(MAIN_BIN) .

# Build all plugins (excluding "internal")
build-plugins:
	@echo "Building plugins with tags $(BUILD_TAGS)..."
	@mkdir -p $(BIN_DIR)
	@for dir in $(PLUGIN_NAMES); do \
		echo "Building plugin $dir with tags $(BUILD_TAGS)..."; \
		cd $(PLUGIN_DIR)/$dir && go build -tags "$(BUILD_TAGS)" -o ../../$(BIN_DIR)/sshpiperd-$dir; \
		cd -; \
	done

# Combined build target (main and plugins)
build: build-main build-plugins

# Run tests for all modules (main + plugins)
test:
	@echo "Running tests..."
	go test ./...

# Run e2e tests
e2e:
	@echo "Running e2e tests..."
	go test ./e2e/... -tags=e2e

# Docker build for local image (para a plataforma atual)
docker-local: build
	@echo "Building local Docker image for $(IMAGE):$(TAG)..."
	docker build -t $(IMAGE):$(TAG) .

# Docker build and push for multi-arch images (amd64 and arm64)
docker-build-push: build
	@echo "Building and pushing multi-arch Docker image for $(IMAGE):$(TAG)..."
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE):$(TAG) --push .

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -rf $(BIN_DIR)
	rm -f ./bin/kind

# Cross-compile main binary for amd64 and arm64
build-main-amd64:
	@echo "Building main program for linux/amd64..."
	@mkdir -p $(BIN_DIR)/amd64
	GOOS=linux GOARCH=amd64 go build -tags "$(BUILD_TAGS)" -o $(BIN_DIR)/amd64/sshpiperd ./$(MAIN_DIR)

build-main-arm64:
	@echo "Building main program for linux/arm64..."
	@mkdir -p $(BIN_DIR)/arm64
	GOOS=linux GOARCH=arm64 go build -tags "$(BUILD_TAGS)" -o $(BIN_DIR)/arm64/sshpiperd ./$(MAIN_DIR)

# Cross-compile yaml plugin for amd64 and arm64
build-yaml-amd64:
	@echo "Building yaml plugin for linux/amd64..."
	@mkdir -p $(BIN_DIR)/amd64
	GOOS=linux GOARCH=amd64 go build -tags "$(BUILD_TAGS)" -o $(BIN_DIR)/amd64/yaml ./plugin/yaml

build-yaml-arm64:
	@echo "Building yaml plugin for linux/arm64..."
	@mkdir -p $(BIN_DIR)/arm64
	GOOS=linux GOARCH=arm64 go build -tags "$(BUILD_TAGS)" -o $(BIN_DIR)/arm64/yaml ./plugin/yaml

# Build all cross-arch binaries needed for packaging
build-cross: build-main-amd64 build-main-arm64 build-yaml-amd64 build-yaml-arm64

# Package tarballs for each architecture
package-tarballs: build-cross
	@echo "Packaging tarballs for amd64 and arm64..."
	cd $(BIN_DIR)/arm64 && tar -czvf ../../sshpiper_aarch64.tar.gz sshpiperd yaml
	cd $(BIN_DIR)/amd64 && tar -czvf ../../sshpiper_x86_64.tar.gz sshpiperd yaml
	@echo "Tarballs created: sshpiper_aarch64.tar.gz, sshpiper_x86_64.tar.gz"

# Clean cross-arch build artifacts and tarballs
clean-cross:
	@echo "Cleaning cross-arch build artifacts and tarballs..."
	rm -rf $(BIN_DIR)/amd64 $(BIN_DIR)/arm64 sshpiper_aarch64.tar.gz sshpiper_x86_64.tar.gz

# Documentation for new targets
# build-cross: Build main binary and yaml plugin for linux/amd64 and linux/arm64
# package-tarballs: Create tar.gz packages for each architecture (main binary + yaml plugin)
# clean-cross: Remove cross-arch build artifacts and tarballs

# Run the full E2E suite using docker-compose (matches CI workflow)
e2e-all:
	@echo "Running full E2E suite with docker-compose..."
	cd e2e && COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker compose up --build --abort-on-container-exit --exit-code-from testrunner

# Kind cluster management for local Kubernetes E2E
.PHONY: kind-up kind-down kind-status kind-load

# Prerequisites automation for local k8s-proxy E2E
.PHONY: prereqs

# Install kind if not present and check Docker is running
prereqs:
	@if ! command -v kind >/dev/null 2>&1 && [ ! -x ./bin/kind ]; then \
	  echo "kind not found, installing to ./bin/kind..."; \
	  mkdir -p ./bin; \
	  curl -Lo ./bin/kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64; \
	  chmod +x ./bin/kind; \
	fi
	@if ! docker info >/dev/null 2>&1; then \
	  echo "Docker is not running or not available. Please start Docker."; \
	  exit 1; \
	fi

# Use local kind if present, else system kind
KIND_BIN := $(shell [ -x ./bin/kind ] && echo ./bin/kind || echo kind)

kind-up:
	PATH=./bin:$$PATH $(KIND_BIN) create cluster -n sshpipertest || true

kind-down:
	PATH=./bin:$$PATH $(KIND_BIN) delete cluster -n sshpipertest || true

kind-status:
	PATH=./bin:$$PATH $(KIND_BIN) get clusters
	PATH=./bin:$$PATH $(KIND_BIN) get nodes -n sshpipertest || true

kind-load:
	docker build -t sshpiper-test-image .
	PATH=./bin:$$PATH $(KIND_BIN) load docker-image -n sshpipertest sshpiper-test-image

# e2e-all now depends on kind-up and kind-load for k8s-proxy E2E
.PHONY: e2e-all-full

e2e-all-full: prereqs kind-up kind-load
	$(MAKE) e2e-all

# Test the local kind binary
.PHONY: kind-local
kind-local:
	PATH=./bin:$$PATH ./bin/kind version

# Build all E2E test plugins for test runner
.PHONY: build-e2e-plugins
build-e2e-plugins:
	@echo "Building E2E test plugins..."
	go build -tags "e2e" -o e2e/testplugin/testsetmetaplugin/testsetmetaplugin ./e2e/testplugin/testsetmetaplugin
	go build -tags "e2e" -o e2e/testplugin/testgetmetaplugin/testgetmetaplugin ./e2e/testplugin/testgetmetaplugin
	go build -tags "e2e" -o e2e/testplugin/testgrpcplugin/testgrpcplugin ./e2e/testplugin/testgrpcplugin
