# SSHPiper E2E Testing Suite

Comprehensive End-to-End testing framework for SSHPiper with complete coverage of all plugins, SSH server versions, and operational scenarios.

## 🎯 Overview

This E2E testing suite provides:

- **Complete Plugin Coverage**: Docker, Kubernetes, YAML plugins
- **SSH Server Compatibility**: OpenSSH 7.x, 8.x, 9.x, Dropbear
- **Load Testing**: Concurrent connections, rapid cycling, scaling scenarios  
- **Security Validation**: Authentication, authorization, input validation
- **Failure Recovery**: Error handling, failover, retry mechanisms
- **Performance Benchmarks**: Throughput, latency, resource usage

## 📋 Prerequisites

### Required Tools
- **Go 1.24+**: For test execution
- **Docker**: For containerized SSH servers and plugin testing
- **kubectl**: For Kubernetes plugin testing
- **Make**: For automated test execution

### Environment Setup
```bash
# Install dependencies
make install-deps

# Check prerequisites
make check-prereqs

# Setup test environment
make setup
```

### Environment Variables
```bash
export INTEGRATION_TESTS=1      # Enable integration tests
export LOAD_TESTS=1             # Enable load tests (optional)
export KUBECONFIG=~/.kube/config # Kubernetes config file
export DOCKER_HOST=unix:///var/run/docker.sock
```

## 🚀 Quick Start

### Run All Tests
```bash
# Complete test suite (60+ minutes)
make test-all

# Quick smoke tests (10 minutes)
make test-smoke

# Parallel execution (faster)
make test-parallel
```

### Individual Plugin Tests
```bash
# Docker plugin tests
make test-docker

# Kubernetes plugin tests
make test-kubernetes

# YAML plugin tests
make test-yaml
```

### SSH Version Compatibility
```bash
# All SSH server versions
make test-ssh-versions

# Specific version
make test-ssh-version-OpenSSH_9.0
make test-ssh-version-Dropbear_2022
```

## 📊 Test Structure

### Comprehensive Integration Tests (`comprehensive_integration_test.go`)
- **Multi-plugin scenarios**: Docker + Kubernetes + YAML
- **Cross-version compatibility**: All SSH server versions
- **Load testing**: Concurrent connections, scaling
- **Failure scenarios**: Network issues, authentication failures

### Plugin-Specific Tests

#### Docker Plugin Tests (`enhanced_docker_test.go`)
- Container discovery via Docker labels
- Container lifecycle management (start/stop/restart)
- Multi-container load balancing
- Network isolation and security
- Volume mounting functionality
- Environment variable injection
- Health checks and auto-scaling
- Failure recovery mechanisms

#### Kubernetes Plugin Tests (`enhanced_kubernetes_test.go`)
- CRD-based pipe discovery
- Secret-based credential management
- RBAC authorization validation
- Namespace isolation
- ConfigMap integration
- Service discovery
- Pod lifecycle management
- Ingress routing
- Persistent volumes
- Network policies
- Resource quotas
- Monitoring integration

#### YAML Plugin Tests (`enhanced_yaml_test.go`)
- Basic password authentication
- Regex username matching
- Environment variable expansion
- Public key authentication
- Multiple target hosts
- Failover routing
- Host key validation
- Load balancing
- CA signed certificates
- Complex routing scenarios
- Banned user handling
- Rate limiting
- Configuration reload
- Template processing
- Security validation

### SSH Server Compatibility (`ssh_version_compatibility_test.go`)
- **OpenSSH versions**: 7.4, 8.0, 8.4, 8.9, 9.0
- **Alternative implementations**: Dropbear SSH
- **Authentication methods**: Password, public key, keyboard-interactive
- **Protocol features**: Ed25519, ECDSA, RSA-SHA2
- **Cipher support**: AES-CTR, AES-GCM, ChaCha20-Poly1305
- **Plugin compatibility**: Fixed, YAML, Docker with each SSH version

## 🔧 Configuration

### Test Configurations

#### Docker Plugin (`plugin_configs/docker_test_config.yml`)
```yaml
services:
  ssh-target-1:
    image: linuxserver/openssh-server:latest
    labels:
      - "sshpiper.host=ssh-target-1"
      - "sshpiper.port=2222"
      - "sshpiper.auth=password"
```

#### Kubernetes Plugin (`plugin_configs/kubernetes_test_config.yaml`)
```yaml
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: test-pipe-password
spec:
  from:
    - username: k8suser
  to:
    host: ssh-target-service:2222
    password_secret:
      name: ssh-credentials
      key: password
```

#### YAML Plugin (`plugin_configs/yaml_test_config.yml`)
```yaml
version: "1.0"
pipes:
  - from:
      - username: "yamluser"
    to:
      host: "${TEST_HOST}"
      username: "${TEST_USER}"
      password: "${TEST_PASSWORD}"
      ignore_hostkey: true
```

## 📈 Test Execution

### Standard Test Runs

#### Full Test Suite
```bash
make test-all
```
**Duration**: 60-90 minutes  
**Coverage**: All plugins, all SSH versions, load tests, security tests

#### Plugin-Specific Tests
```bash
# Docker plugin (15-20 minutes)
make test-docker

# Kubernetes plugin (20-25 minutes) 
make test-kubernetes

# YAML plugin (10-15 minutes)
make test-yaml
```

#### SSH Version Compatibility
```bash
# All SSH server versions (45-60 minutes)
make test-ssh-versions

# Specific SSH version (5-10 minutes each)
make test-ssh-openssh-8
make test-ssh-openssh-9
make test-ssh-dropbear
```

### Performance Testing

#### Load Tests
```bash
# Enable load testing
export LOAD_TESTS=1

# Run load scenarios
make test-load
```

**Load Test Scenarios**:
- 10 concurrent connections
- 50 rapid connection cycles
- Auto-scaling validation
- Memory/CPU usage under load

#### Benchmarks
```bash
# Performance benchmarks
make benchmark-all
```

### Security Testing

#### Security Validation
```bash
make test-security
```

**Security Test Coverage**:
- Authentication bypass attempts
- Authorization escalation tests
- Input validation (SQL injection, command injection)
- Network isolation validation
- Credential security (no plaintext storage)
- Host key validation
- Certificate authority validation

### Debugging and Development

#### Debug Mode
```bash
make test-debug
```
Enables verbose logging and debug output for troubleshooting.

#### Individual Test Cases
```bash
# Specific test function
go test -v ./enhanced_docker_test.go ./main_test.go -run TestDockerLabelDiscovery

# With environment setup
INTEGRATION_TESTS=1 go test -v ./enhanced_yaml_test.go ./main_test.go -run TestYAMLRegexUsernameMatching
```

## 📊 Test Reports

### Generate Reports
```bash
make report
```

**Generated Reports**:
- `test-results/reports/summary.md`: Overall test summary
- `test-results/coverage.html`: Code coverage report
- `ssh_compatibility_report.md`: SSH version compatibility matrix

### Coverage Analysis
```bash
make test-coverage
```

Opens detailed HTML coverage report showing:
- Line-by-line coverage
- Function coverage
- Branch coverage
- Package-level statistics

### Continuous Integration

#### CI/CD Pipeline Tests
```bash
# JSON output for CI systems
make ci-all

# Individual CI tests
make ci-docker
make ci-kubernetes  
make ci-yaml
```

## 🛠️ Troubleshooting

### Common Issues

#### Docker Permission Issues
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart docker service
sudo systemctl restart docker
```

#### Kubernetes Connection Issues
```bash
# Verify kubectl access
kubectl cluster-info

# Check KUBECONFIG
echo $KUBECONFIG

# Test connection
kubectl get nodes
```

#### Test Timeout Issues
```bash
# Increase timeout for slow systems
go test -timeout 45m ./comprehensive_integration_test.go
```

#### Container Cleanup Issues
```bash
# Manual cleanup
make clean-all

# Remove stuck containers
docker system prune -a -f
```

### Debug Logs

#### Enable Debug Logging
```bash
# Set debug environment
export DEBUG=1
export VERBOSE=1

# Run with debug output
make test-debug
```

#### View Test Logs
```bash
# Real-time log viewing
tail -f test-results/comprehensive-test.log

# Search for specific errors
grep -i error test-results/*.log
```

## 🔄 Maintenance

### Regular Maintenance Tasks

#### Update SSH Server Images
```bash
# Pull latest images
docker pull linuxserver/openssh-server:latest
docker pull rastasheep/ubuntu-sshd:latest

# Clean old images
docker image prune -a
```

#### Cleanup Test Artifacts
```bash
# Standard cleanup
make clean

# Full cleanup including images
make clean-all
```

#### Update Test Dependencies
```bash
# Update Go modules
go mod tidy
go get -u ./...

# Install updated dependencies
make install-deps
```

### Adding New Tests

#### New Plugin Test
1. Create `enhanced_[plugin]_test.go`
2. Implement `Test[Plugin]PluginComprehensive` function
3. Add configuration in `plugin_configs/`
4. Update Makefile with `test-[plugin]` target

#### New SSH Server Version
1. Add entry to `sshServerVersions` slice in `ssh_version_compatibility_test.go`
2. Define Docker image, features, and known issues
3. Update compatibility matrix generator
4. Add specific test target in Makefile

#### New Test Scenario
1. Add test function to appropriate test file
2. Follow naming convention: `test[Feature][Scenario]`
3. Use standardized test parameters and validation
4. Update test documentation

## 📋 Test Matrix

### Current Test Coverage

| Plugin | SSH Versions | Auth Methods | Load Tests | Security Tests |
|--------|--------------|--------------|------------|----------------|
| Docker | All | Password, Key | ✅ | ✅ |
| Kubernetes | All | Password, Key, RBAC | ✅ | ✅ |
| YAML | All | Password, Key, Regex | ✅ | ✅ |
| Fixed | All | Password, Key | ✅ | ✅ |

### SSH Server Compatibility

| SSH Server | Version | Password Auth | Public Key Auth | Ed25519 | ECDSA | Known Issues |
|------------|---------|---------------|-----------------|---------|-------|--------------|
| OpenSSH_7.4 | 7.2p2 | ✅ | ✅ | ❌ | ✅ | older-cipher-support |
| OpenSSH_8.0 | 7.6p1 | ✅ | ✅ | ✅ | ✅ | - |
| OpenSSH_8.4 | 8.2p1 | ✅ | ✅ | ✅ | ✅ | - |
| OpenSSH_8.9 | 8.9p1 | ✅ | ✅ | ✅ | ✅ | - |
| OpenSSH_9.0 | 9.0p1 | ✅ | ✅ | ✅ | ✅ | - |
| Dropbear | 2022.83 | ✅ | ✅ | ⚠️ | ⚠️ | limited-cipher-support |

## 🎯 Best Practices

### Test Development
- **Isolated Tests**: Each test should be independent
- **Proper Cleanup**: Always cleanup resources in defer statements
- **Timeout Handling**: Set appropriate timeouts for all operations
- **Error Validation**: Test both success and failure scenarios
- **Logging**: Use structured logging for debugging

### Performance Considerations
- **Parallel Execution**: Use `-parallel` flag for independent tests
- **Resource Limits**: Monitor Docker memory/CPU usage
- **Cleanup**: Regular cleanup prevents resource exhaustion
- **Selective Testing**: Run specific tests during development

### Security Testing
- **No Hardcoded Secrets**: Use environment variables or temporary files
- **Proper Isolation**: Ensure tests don't interfere with each other
- **Input Validation**: Test boundary conditions and malicious inputs
- **Authentication Testing**: Verify all authentication methods
- **Authorization Testing**: Test permission boundaries

## 📞 Support

### Getting Help
- **Documentation**: This README and inline code comments
- **Logs**: Check test-results/*.log files for detailed output
- **Debug Mode**: Use `make test-debug` for verbose output
- **Issues**: Create GitHub issues for bugs or feature requests

### Contributing
- **Test Standards**: Follow existing test patterns and naming
- **Documentation**: Update this README for new features
- **Coverage**: Maintain >90% test coverage
- **Review**: All test changes require code review