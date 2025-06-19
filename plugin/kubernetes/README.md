# Kubernetes Plugin

## Overview

The Kubernetes plugin provides SSH pipe configuration through Kubernetes Custom Resource Definitions (CRDs). It allows dynamic SSH routing configuration stored as Kubernetes resources, with support for secrets and configmaps.

## Features

- **CRD-based configuration**: Uses Kubernetes Pipe CRDs for configuration
- **Secrets integration**: Supports Kubernetes secrets for sensitive data
- **ConfigMap support**: Uses ConfigMaps for non-sensitive configuration
- **Standardized helpers**: Uses libplugin.Standard* functions for consistent behavior
- **Dynamic updates**: Automatically updates when CRDs change
- **Multi-namespace support**: Works across different Kubernetes namespaces

## Prerequisites

- Kubernetes cluster access
- Proper RBAC permissions for reading Pipes, Secrets, and ConfigMaps
- kubectl configured with appropriate context

## Configuration

### RBAC Setup

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sshpiper-kubernetes-plugin
rules:
- apiGroups: ["sshpiper.com"]
  resources: ["pipes"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sshpiper-kubernetes-plugin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: sshpiper-kubernetes-plugin
subjects:
- kind: ServiceAccount
  name: sshpiper
  namespace: sshpiper-system
```

### Command Line Options

- `--kubernetes-config`: Path to kubeconfig file
- `--kubernetes-namespace`: Namespace to watch for Pipe resources
- `--kubernetes-label-selector`: Label selector for filtering Pipes

## Custom Resource Definition

### Pipe CRD Structure

```yaml
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: example-pipe
  namespace: default
spec:
  from:
    - username: "user1"
      authorized_keys_data: "ssh-rsa AAAAB3NzaC1yc2E..."
      htpasswd_data: "user1:$2y$10$..."
    - username_regex: "dev-.*"
      username_regex_match: true
      authorized_keys_file: "/path/to/keys"
  to:
    host: "backend.example.com:22"
    username: "backend-user"
    private_key_data: "-----BEGIN PRIVATE KEY-----..."
    known_hosts_data: "backend.example.com ssh-rsa AAAAB3..."
    ignore_hostkey: false
```

## Authentication Methods

### Password Authentication

- Uses `libplugin.StandardTestPassword` for consistent password validation
- Supports htpasswd format in CRD data or referenced secrets
- Integrates with Kubernetes secrets for secure password storage

### Public Key Authentication

- Uses `libplugin.StandardAuthorizedKeys` for key loading
- Supports inline key data in CRDs or references to secrets/configmaps
- Handles multiple key formats and sources

### Certificate Authentication

- Uses `libplugin.StandardTrustedUserCAKeys` for CA key loading
- Validates certificates against trusted CA keys stored in secrets
- Supports certificate-based authentication workflows

## Kubernetes Integration

### Secrets Support

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ssh-keys
  namespace: default
type: Opaque
data:
  authorized_keys: <base64-encoded-keys>
  private_key: <base64-encoded-private-key>
  password: <base64-encoded-password>
```

Reference in Pipe:

```yaml
spec:
  from:
    - username: "user1"
      authorized_keys_secret: "ssh-keys"
      authorized_keys_secret_key: "authorized_keys"
```

### ConfigMap Support

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssh-config
  namespace: default
data:
  known_hosts: |
    backend.example.com ssh-rsa AAAAB3NzaC1yc2E...
  upstream_config: |
    backend.example.com:22
    backend-user
```

## Standardized Features

### Helper Functions Used

- `StandardTestPassword`: Password authentication with Kubernetes secrets
- `StandardAuthorizedKeys`: Public key loading from secrets/configmaps
- `StandardTrustedUserCAKeys`: CA key loading from Kubernetes resources
- Kubernetes API integration for dynamic configuration loading

### Environment Variables

- `DOWNSTREAM_USER`: Username of connecting client
- `KUBERNETES_NAMESPACE`: Current namespace context
- `POD_NAME`: Pod name for logging context

## Security Features

- **RBAC integration**: Proper Kubernetes RBAC for resource access
- **Secret encryption**: Leverages Kubernetes secret encryption at rest
- **Namespace isolation**: Supports multi-tenant namespace separation
- **Audit logging**: Kubernetes audit logs for configuration changes

## Examples

### Basic Pipe Configuration

```yaml
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: developer-access
  namespace: development
spec:
  from:
    - username: "alice"
      authorized_keys_data: "ssh-rsa AAAAB3NzaC1yc2E... alice@dev"
    - username: "bob"
      authorized_keys_data: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... bob@dev"
  to:
    host: "dev-backend.internal:22"
    username: "developer"
    private_key_data: "-----BEGIN PRIVATE KEY-----\n..."
    known_hosts_data: "dev-backend.internal ssh-rsa AAAAB3..."
```

### Regex-based Routing

```yaml
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: team-routing
  namespace: production
spec:
  from:
    - username_regex: "team-([a-z]+)-.*"
      username_regex_match: true
      authorized_keys_secret: "team-keys"
      authorized_keys_secret_key: "authorized_keys"
  to:
    host: "prod-backend-${TEAM}.internal:22"
    username: "service-account"
    private_key_secret: "service-keys"
    private_key_secret_key: "private_key"
```

### Secret-based Configuration

```yaml
# Secret with SSH keys
apiVersion: v1
kind: Secret
metadata:
  name: production-keys
  namespace: production
type: Opaque
data:
  authorized_keys: <base64-encoded-keys>
  private_key: <base64-encoded-private-key>
  known_hosts: <base64-encoded-known-hosts>
---
# Pipe using the secret
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: production-access
  namespace: production
spec:
  from:
    - username: "admin"
      authorized_keys_secret: "production-keys"
      authorized_keys_secret_key: "authorized_keys"
  to:
    host: "production.internal:22"
    username: "admin"
    private_key_secret: "production-keys"
    private_key_secret_key: "private_key"
    known_hosts_secret: "production-keys"
    known_hosts_secret_key: "known_hosts"
```

## Deployment

### Using Helm

```bash
helm install sshpiper-kubernetes ./charts/sshpiper-kubernetes \
  --set kubernetes.namespace=sshpiper-system \
  --set rbac.create=true
```

### Using kubectl

```bash
kubectl apply -f kubernetes-plugin-rbac.yaml
kubectl apply -f kubernetes-plugin-deployment.yaml
```

## Monitoring and Observability

### Metrics

- Pipe configuration load count
- Authentication attempt metrics
- Kubernetes API call metrics
- Error rate tracking

### Logging

- Structured JSON logging
- Kubernetes context in logs
- Authentication event logging
- Configuration change tracking

### Health Checks

- Kubernetes API connectivity
- CRD availability checks
- Secret/ConfigMap access validation

## Troubleshooting

### Common Issues

1. **RBAC permissions**: Verify service account has proper permissions
2. **CRD not found**: Ensure Pipe CRDs are installed
3. **Secret access denied**: Check RBAC for secret access
4. **Connection failures**: Verify backend connectivity from cluster

### Debug Commands

```bash
# Check Pipe resources
kubectl get pipes -A

# Describe specific pipe
kubectl describe pipe example-pipe -n default

# Check plugin logs
kubectl logs -l app=sshpiper-kubernetes -f

# Verify RBAC
kubectl auth can-i get pipes --as=system:serviceaccount:sshpiper-system:sshpiper
```

## Best Practices

1. **Security**: Use secrets for sensitive data, never plain text in CRDs
2. **Organization**: Use namespaces for tenant isolation
3. **Monitoring**: Set up proper monitoring and alerting
4. **Backup**: Backup CRD configurations regularly
5. **Updates**: Use GitOps for CRD configuration management

## Migration and Upgrades

### From File-based Configuration

1. Convert file-based configs to Pipe CRDs
2. Migrate secrets to Kubernetes secrets
3. Set up proper RBAC permissions
4. Test thoroughly before production deployment

### Version Upgrades

1. Check CRD compatibility
2. Update RBAC permissions if needed
3. Test in staging environment first
4. Monitor for deprecation warnings
