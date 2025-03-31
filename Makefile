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

.PHONY: all vendor fmt vet lint check codegen codegen-k8s gen-main build-main build-plugins build docker-local docker-build-push test clean

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
		echo "Building plugin $$dir with tags $(BUILD_TAGS)..."; \
		cd $(PLUGIN_DIR)/$$dir && go build -tags "$(BUILD_TAGS)" -o ../../$(BIN_DIR)/sshpiperd-$$dir; \
		cd -; \
	done

# Combined build target (main and plugins)
build: build-main build-plugins

# Run tests for all modules (main + plugins)
test:
	@echo "Running tests..."
	go test ./...

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
