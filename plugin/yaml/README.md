# YAML Plugin

## Overview

The YAML plugin provides SSH pipe configuration through YAML files with support for multiple authentication methods, regex-based routing, and standardized helper functions. It offers flexible configuration management with file-based persistence.

## Features

- **YAML-based configuration**: Human-readable configuration files
- **Multiple authentication methods**: Password, public key, and certificate authentication
- **Regex routing**: Advanced username matching with regular expressions
- **Group-based access**: Unix group membership validation
- **Standardized helpers**: Uses libplugin.Standard* functions for consistent behavior
- **Hot reload**: Dynamic configuration reloading without restart
- **Environment variable expansion**: Dynamic configuration with environment variables

## Configuration

### Command Line Options

- `--yaml-file`: Path to YAML configuration files (supports glob patterns)
- `--yaml-nocheckperm`: Skip file permission checks

### YAML Configuration Format

```yaml
version: "1.0"
pipes:
  - from:
      - username: "alice"
        authorized_keys_data: "ssh-rsa AAAAB3NzaC1yc2E..."
        htpasswd_data: "alice:$2y$10$..."
      - username_regex: "dev-.*"
        username_regex_match: true
        authorized_keys: "/path/to/dev-keys"
        groupname: "developers"
    to:
      host: "backend.example.com:22"
      username: "backend-user"
      private_key: "/path/to/private-key"
      known_hosts_data: "backend.example.com ssh-rsa AAAAB3..."
      ignore_hostkey: false
```

## Authentication Methods

### Password Authentication

- **htpasswd_data**: Inline htpasswd entries (base64 encoded)
- **htpasswd_file**: Path to htpasswd file
- Uses `libplugin.StandardTestPassword` for consistent validation
- Supports multiple password formats (bcrypt, MD5, SHA, etc.)

### Public Key Authentication

- **authorized_keys_data**: Inline SSH public keys (base64 encoded)
- **authorized_keys**: Path to authorized_keys file or list of paths
- Uses `libplugin.StandardAuthorizedKeys` for key loading
- Supports multiple key formats (RSA, Ed25519, ECDSA)

### Certificate Authentication

- **trusted_user_ca_keys_data**: Inline CA keys (base64 encoded)
- **trusted_user_ca_keys**: Path to CA keys file or list of paths
- Uses `libplugin.StandardTrustedUserCAKeys` for CA validation
- Supports certificate-based authentication

## Advanced Routing

### Username Matching

#### Exact Match

```yaml
from:
  - username: "alice"
    authorized_keys_data: "ssh-rsa AAAAB3..."
```

#### Regex Match

```yaml
from:
  - username_regex: "team-([a-z]+)-.*"
    username_regex_match: true
    authorized_keys: "/keys/${TEAM}/authorized_keys"
```

#### Group-based Access

```yaml
from:
  - username_regex: ".*"
    username_regex_match: true
    groupname: "ssh-users"
    authorized_keys: "/keys/group-keys"
```

### Multiple Sources

```yaml
from:
  - username: "admin"
    authorized_keys:
      - "/keys/admin/primary"
      - "/keys/admin/backup"
    trusted_user_ca_keys:
      - "/ca/admin-ca.pub"
      - "/ca/root-ca.pub"
```

## Upstream Configuration

### Basic Configuration

```yaml
to:
  host: "backend.example.com:22"
  username: "service-account"
  ignore_hostkey: true
```

### With Authentication

```yaml
to:
  host: "secure-backend.example.com:22"
  username: "authenticated-user"
  private_key: "/keys/backend-key"
  private_key_data: "-----BEGIN PRIVATE KEY-----..."
  password: "backend-password"
  known_hosts: "/config/known_hosts"
  known_hosts_data: "secure-backend.example.com ssh-rsa AAAAB3..."
```

## Standardized Features

### Helper Functions Used

- `StandardTestPassword`: Password authentication with htpasswd support
- `StandardAuthorizedKeys`: Public key loading with environment expansion
- `StandardTrustedUserCAKeys`: CA key loading for certificate validation
- `StandardKnownHosts`: Known hosts loading for upstream verification
- `StandardPrivateKey`: Private key loading for upstream authentication
- `StandardOverridePassword`: Password override functionality

### Environment Variables

- `DOWNSTREAM_USER`: Username of connecting client
- `UPSTREAM_USER`: Username for upstream connection
- Custom variables can be used in file paths with `${VARIABLE}` syntax

## Data Formats

### Base64 Encoding

For inline data, use base64 encoding:

```yaml
authorized_keys_data: "c3NoLXJzYSBBQUFBQjNOemFDMXljMkU..."
htpasswd_data: "YWxpY2U6JDJ5JDEwJC4uLg=="
private_key_data: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t..."
```

### File References

For file-based data:

```yaml
authorized_keys: "/path/to/authorized_keys"
htpasswd_file: "/path/to/htpasswd"
private_key: "/path/to/private_key"
```

### List Support

Multiple sources can be specified:

```yaml
authorized_keys:
  - "/keys/primary"
  - "/keys/backup"
known_hosts_data:
  - "host1.example.com ssh-rsa AAAAB3..."
  - "host2.example.com ssh-ed25519 AAAAC3..."
```

## Examples

### Basic User Access

```yaml
version: "1.0"
pipes:
  - from:
      - username: "alice"
        authorized_keys_data: "ssh-rsa AAAAB3NzaC1yc2E... alice@laptop"
      - username: "bob"
        htpasswd_data: "bob:$2y$10$rQ7QZ8zX..."
    to:
      host: "web-server.internal:22"
      username: "webadmin"
      private_key: "/keys/webadmin-key"
      ignore_hostkey: true
```

### Development Team Access

```yaml
version: "1.0"
pipes:
  - from:
      - username_regex: "dev-.*"
        username_regex_match: true
        groupname: "developers"
        authorized_keys: "/keys/dev-team/authorized_keys"
    to:
      host: "dev-environment.internal:22"
      username: "developer"
      private_key_data: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t..."
      known_hosts_data: "dev-environment.internal ssh-rsa AAAAB3..."
```

### Multi-Environment Routing

```yaml
version: "1.0"
pipes:
  - from:
      - username_regex: "prod-([a-z]+)"
        username_regex_match: true
        authorized_keys: "/keys/production/authorized_keys"
        trusted_user_ca_keys: "/ca/production-ca.pub"
    to:
      host: "prod-${SERVICE}.internal:22"
      username: "service-account"
      private_key: "/keys/production/service-key"
      known_hosts: "/config/production-known_hosts"
  - from:
      - username_regex: "staging-([a-z]+)"
        username_regex_match: true
        authorized_keys: "/keys/staging/authorized_keys"
    to:
      host: "staging-${SERVICE}.internal:22"
      username: "staging-user"
      private_key: "/keys/staging/service-key"
      ignore_hostkey: true
```

### Certificate-based Authentication

```yaml
version: "1.0"
pipes:
  - from:
      - username: "cert-user"
        trusted_user_ca_keys_data: "ssh-rsa AAAAB3NzaC1yc2E... ca@company"
    to:
      host: "secure-server.internal:22"
      username: "authenticated-user"
      private_key: "/keys/client-cert-key"
      known_hosts_data: "secure-server.internal ssh-rsa AAAAB3..."
```

## File Management

### Configuration Reloading

The plugin supports hot reloading of configuration files:

```bash
# Send SIGHUP to reload configuration
kill -HUP $(pidof sshpiperd)
```

### File Permissions

Recommended file permissions:

```bash
chmod 600 /etc/sshpiper/config.yaml
chmod 600 /keys/private-keys/*
chmod 644 /keys/authorized_keys/*
```

### Directory Structure

```
/etc/sshpiper/
├── config.yaml
├── keys/
│   ├── authorized_keys/
│   │   ├── team-a
│   │   └── team-b
│   ├── private_keys/
│   │   ├── backend-key
│   │   └── service-key
│   └── ca/
│       ├── root-ca.pub
│       └── intermediate-ca.pub
└── config/
    ├── known_hosts
    └── htpasswd
```

## Security Features

- **Input validation**: Comprehensive validation of all configuration parameters
- **File permission checks**: Validates file permissions for security
- **Environment variable expansion**: Secure handling of dynamic configurations
- **Base64 encoding**: Safe handling of binary data in YAML
- **Group membership validation**: Unix group-based access control

## Monitoring and Observability

### Logging

- Structured JSON logging with context
- Authentication attempt logging
- Configuration reload events
- Error tracking with detailed context

### Metrics

- Configuration load count
- Authentication success/failure rates
- File access metrics
- Performance timing data

## Troubleshooting

### Common Issues

1. **Configuration syntax errors**: Validate YAML syntax
2. **File permission denied**: Check file permissions and ownership
3. **Authentication failures**: Verify key formats and htpasswd entries
4. **Regex not matching**: Test regex patterns with sample usernames

### Debug Commands

```bash
# Validate YAML syntax
yamllint /etc/sshpiper/config.yaml

# Test regex patterns
echo "dev-alice" | grep -E "dev-.*"

# Check file permissions
ls -la /keys/authorized_keys/

# Enable debug logging
sshpiperd --yaml-file /etc/sshpiper/config.yaml --log-level debug
```

### Validation Tools

```bash
# Test htpasswd entries
htpasswd -v /config/htpasswd username

# Validate SSH keys
ssh-keygen -l -f /keys/authorized_keys/team-a

# Check known_hosts format
ssh-keygen -F hostname -f /config/known_hosts
```

## Best Practices

1. **Security**: Use proper file permissions and ownership
2. **Organization**: Structure configuration files logically
3. **Validation**: Validate configuration before deployment
4. **Backup**: Regularly backup configuration and key files
5. **Monitoring**: Set up logging and monitoring for authentication events
6. **Documentation**: Document regex patterns and routing logic

## Migration and Integration

### From Other Plugins

#### From Working Directory Plugin

1. Convert directory structure to YAML configuration
2. Migrate individual user files to centralized config
3. Update file paths and references

#### From Fixed Plugin

1. Extract hardcoded values to YAML configuration
2. Add flexibility with regex patterns
3. Implement proper authentication methods

### Integration with External Systems

#### LDAP Integration

```yaml
from:
  - username_regex: ".*"
    username_regex_match: true
    groupname: "ssh-users"  # LDAP group
    authorized_keys: "/ldap-keys/${DOWNSTREAM_USER}"
```

#### CI/CD Pipeline

```yaml
# Automated deployment configuration
from:
  - username: "deploy-bot"
    authorized_keys_data: "${DEPLOY_BOT_KEY}"
to:
  host: "${DEPLOY_TARGET}:22"
  username: "deploy"
  private_key_data: "${DEPLOY_PRIVATE_KEY}"
```

## Performance Optimization

### Caching

- Configuration caching for improved performance
- Key file caching to reduce disk I/O
- Regex compilation caching

### Resource Management

- Efficient memory usage for large configurations
- Optimized file reading for better performance
- Connection pooling for upstream connections

This documentation provides comprehensive coverage of the YAML plugin's capabilities, configuration options, and best practices for production deployment.
