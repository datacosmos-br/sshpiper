#!/bin/bash

# validate_e2e_setup.sh - Validation script for SSHPiper E2E testing setup
# This script validates that the E2E testing environment is properly configured

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Docker daemon
check_docker() {
    log_info "Checking Docker setup..."
    
    if ! command_exists docker; then
        log_error "Docker is not installed"
        return 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        return 1
    fi
    
    # Test Docker permissions
    if ! docker ps >/dev/null 2>&1; then
        log_error "Cannot access Docker (permission issue?)"
        log_info "Try: sudo usermod -aG docker \$USER && newgrp docker"
        return 1
    fi
    
    log_success "Docker is working correctly"
    
    # Check Docker networks
    if ! docker network ls | grep -q sshpiper-test; then
        log_info "Creating sshpiper-test network..."
        docker network create sshpiper-test || true
    fi
    
    return 0
}

# Check Kubernetes setup
check_kubernetes() {
    log_info "Checking Kubernetes setup..."
    
    if ! command_exists kubectl; then
        log_warning "kubectl is not installed (required for Kubernetes plugin tests)"
        return 1
    fi
    
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_warning "Cannot connect to Kubernetes cluster (Kubernetes tests will be skipped)"
        return 1
    fi
    
    # Check if we can create namespaces
    if kubectl auth can-i create namespaces >/dev/null 2>&1; then
        log_success "Kubernetes is accessible with sufficient permissions"
    else
        log_warning "Limited Kubernetes permissions (some tests may fail)"
    fi
    
    return 0
}

# Check Go setup
check_go() {
    log_info "Checking Go setup..."
    
    if ! command_exists go; then
        log_error "Go is not installed"
        return 1
    fi
    
    # Check Go version
    go_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    required_version="1.24"
    
    if ! printf '%s\n%s\n' "$required_version" "$go_version" | sort -V -C; then
        log_error "Go version $go_version is too old (requires $required_version+)"
        return 1
    fi
    
    log_success "Go version $go_version is compatible"
    
    # Check Go modules
    if [ -f "go.mod" ]; then
        log_info "Checking Go dependencies..."
        if go mod tidy && go mod download; then
            log_success "Go dependencies are ready"
        else
            log_error "Failed to resolve Go dependencies"
            return 1
        fi
    fi
    
    return 0
}

# Check required files
check_files() {
    log_info "Checking E2E test files..."
    
    required_files=(
        "comprehensive_integration_test.go"
        "enhanced_docker_test.go"
        "enhanced_kubernetes_test.go"
        "enhanced_yaml_test.go"
        "ssh_version_compatibility_test.go"
        "main_test.go"
        "Makefile"
        "plugin_configs/docker_test_config.yml"
        "plugin_configs/kubernetes_test_config.yaml"
        "plugin_configs/yaml_test_config.yml"
    )
    
    missing_files=()
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -eq 0 ]; then
        log_success "All required E2E test files are present"
    else
        log_error "Missing required files:"
        for file in "${missing_files[@]}"; do
            log_error "  - $file"
        done
        return 1
    fi
    
    return 0
}

# Test basic compilation
test_compilation() {
    log_info "Testing Go compilation..."
    
    # Test main package compilation
    if go build -o /tmp/sshpiperd ./cmd/sshpiperd; then
        log_success "Main sshpiperd binary compiles successfully"
        rm -f /tmp/sshpiperd
    else
        log_error "Failed to compile main sshpiperd binary"
        return 1
    fi
    
    # Test plugin compilation
    plugins=("docker" "kubernetes" "yaml" "fixed")
    for plugin in "${plugins[@]}"; do
        if [ -d "./plugin/$plugin" ]; then
            if go build -o "/tmp/plugin-$plugin" "./plugin/$plugin"; then
                log_success "Plugin $plugin compiles successfully"
                rm -f "/tmp/plugin-$plugin"
            else
                log_error "Failed to compile plugin $plugin"
                return 1
            fi
        fi
    done
    
    return 0
}

# Test basic E2E setup
test_e2e_setup() {
    log_info "Testing E2E test compilation..."
    
    # Test if E2E tests compile
    if go test -c ./comprehensive_integration_test.go ./main_test.go -o /tmp/e2e-test; then
        log_success "E2E tests compile successfully"
        rm -f /tmp/e2e-test
    else
        log_error "E2E tests failed to compile"
        return 1
    fi
    
    return 0
}

# Run basic smoke test
run_smoke_test() {
    log_info "Running basic smoke test..."
    
    # Create test environment
    export INTEGRATION_TESTS=1
    
    # Run a minimal test to verify framework works
    if timeout 300 go test -v -timeout 5m ./main_test.go -run "Test.*" 2>/dev/null; then
        log_success "Basic smoke test passed"
    else
        log_warning "Smoke test failed or timed out (this may be normal in some environments)"
    fi
    
    return 0
}

# Pull required Docker images
pull_docker_images() {
    log_info "Pulling required Docker images..."
    
    images=(
        "linuxserver/openssh-server:latest"
        "rastasheep/ubuntu-sshd:20.04"
        "alpine:latest"
    )
    
    for image in "${images[@]}"; do
        log_info "Pulling $image..."
        if docker pull "$image" >/dev/null 2>&1; then
            log_success "Successfully pulled $image"
        else
            log_warning "Failed to pull $image (test may still work with cached images)"
        fi
    done
    
    return 0
}

# Check system resources
check_resources() {
    log_info "Checking system resources..."
    
    # Check available disk space (need at least 5GB)
    available_space=$(df . | tail -1 | awk '{print $4}')
    required_space=5242880  # 5GB in KB
    
    if [ "$available_space" -lt "$required_space" ]; then
        log_warning "Low disk space (${available_space}KB available, 5GB recommended)"
    else
        log_success "Sufficient disk space available"
    fi
    
    # Check available memory (need at least 4GB)
    available_memory=$(free -k | grep '^Mem:' | awk '{print $7}')
    required_memory=4194304  # 4GB in KB
    
    if [ "$available_memory" -lt "$required_memory" ]; then
        log_warning "Low memory (${available_memory}KB available, 4GB recommended)"
    else
        log_success "Sufficient memory available"
    fi
    
    return 0
}

# Main validation function
main() {
    echo "=============================================="
    echo "SSHPiper E2E Testing Environment Validation"
    echo "=============================================="
    echo ""
    
    # Track validation results
    failed_checks=0
    
    # Run all checks
    check_go || ((failed_checks++))
    echo ""
    
    check_docker || ((failed_checks++))
    echo ""
    
    check_kubernetes || true  # Don't fail if Kubernetes is not available
    echo ""
    
    check_files || ((failed_checks++))
    echo ""
    
    test_compilation || ((failed_checks++))
    echo ""
    
    test_e2e_setup || ((failed_checks++))
    echo ""
    
    check_resources || true  # Don't fail on resource warnings
    echo ""
    
    # Optional: Pull Docker images (can be slow)
    if [ "${PULL_IMAGES:-}" = "1" ]; then
        pull_docker_images || true
        echo ""
    fi
    
    # Optional: Run smoke test (can be slow)
    if [ "${RUN_SMOKE_TEST:-}" = "1" ]; then
        run_smoke_test || true
        echo ""
    fi
    
    # Summary
    echo "=============================================="
    echo "Validation Summary"
    echo "=============================================="
    
    if [ $failed_checks -eq 0 ]; then
        log_success "All critical checks passed! E2E testing environment is ready."
        echo ""
        echo "To run E2E tests:"
        echo "  make test-smoke     # Quick smoke tests (~5 minutes)"
        echo "  make test-all       # Full test suite (~60 minutes)"
        echo "  make test-docker    # Docker plugin tests only"
        echo "  make test-yaml      # YAML plugin tests only"
        echo ""
        echo "For more options, run: make help"
        exit 0
    else
        log_error "$failed_checks critical checks failed. Please fix the issues above."
        echo ""
        echo "Common fixes:"
        echo "  - Install missing tools (go, docker, kubectl)"
        echo "  - Start Docker daemon: sudo systemctl start docker"
        echo "  - Add user to docker group: sudo usermod -aG docker \$USER"
        echo "  - Install Go dependencies: go mod tidy"
        exit 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --pull-images)
            export PULL_IMAGES=1
            shift
            ;;
        --smoke-test)
            export RUN_SMOKE_TEST=1
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "OPTIONS:"
            echo "  --pull-images   Pull required Docker images (slow)"
            echo "  --smoke-test    Run basic smoke test (slow)"
            echo "  --help          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                           # Basic validation"
            echo "  $0 --pull-images            # With image pulling"
            echo "  $0 --smoke-test              # With smoke test"
            echo "  $0 --pull-images --smoke-test # Full validation"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main validation
main