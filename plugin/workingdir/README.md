# Working Directory Plugin

## Overview

The Working Directory plugin provides SSH pipe configuration based on a directory structure on the filesystem. It supports both password and public key authentication methods using standardized libplugin helpers.

## Features

- **Directory-based configuration**: Each user has their own directory with configuration files
- **Flexible authentication**: Supports both password and public key authentication
- **Standardized helpers**: Uses libplugin.Standard* functions for consistent behavior
- **Recursive search**: Optional recursive directory search for upstream configurations
- **Security validation**: Username validation and permission checking

## Configuration

### Command Line Options

- `--workingdir-root`: Root directory containing user configurations (default: current directory)
- `--workingdir-allowbadusername`: Allow potentially unsafe usernames
- `--workingdir-nopassword`: Disable password authentication
- `--workingdir-nocheckperm`: Skip file permission checks
- `--workingdir-stricthostkey`: Enable strict host key checking
- `--workingdir-recursivesearch`: Enable recursive search for upstream configs

### Directory Structure

```
/root/
├── user1/
│   ├── authorized_keys    # SSH public keys for authentication
│   ├── id_rsa            # Private key for upstream connection
│   ├── known_hosts       # Known hosts for upstream
│   ├── password          # Password for authentication (optional)
│   ├── trusted_user_ca_keys # Trusted CA keys for certificate auth
│   └── sshpiper_upstream # Upstream configuration
├── user2/
│   └── ...
```

### File Formats

#### sshpiper_upstream

```
host:port
username
```

#### authorized_keys

Standard SSH authorized_keys format:

```
ssh-rsa AAAAB3NzaC1yc2E... user@host
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host
```

#### password

Plain text password or htpasswd format:

```
plaintext_password
```

#### known_hosts

Standard SSH known_hosts format:

```
host.example.com ssh-rsa AAAAB3NzaC1yc2E...
```

## Authentication Methods

### Password Authentication

- Uses `libplugin.StandardTestPassword` for consistent password validation
- Supports htpasswd format for secure password storage
- Falls back to allowing connection if no password file exists

### Public Key Authentication

- Uses `libplugin.StandardAuthorizedKeys` for key loading
- Supports environment variable expansion in file paths
- Handles multiple key formats (RSA, Ed25519, ECDSA)

### Certificate Authentication

- Uses `libplugin.StandardTrustedUserCAKeys` for CA key loading
- Validates certificates against trusted CA keys
- Supports certificate-based authentication

## Standardized Features

### Helper Functions Used

- `StandardTestPassword`: Password authentication
- `StandardAuthorizedKeys`: Public key loading
- `StandardTrustedUserCAKeys`: CA key loading
- `StandardKnownHosts`: Known hosts loading
- `StandardPrivateKey`: Private key loading
- `StandardOverridePassword`: Password override
- `StandardIgnoreHostKey`: Host key validation logic

### Environment Variables

- `DOWNSTREAM_USER`: Username of connecting client
- Automatically expanded in file paths using `${DOWNSTREAM_USER}` syntax

## Security Features

- **Username validation**: Prevents directory traversal attacks
- **Permission checking**: Validates file permissions for security
- **Host key verification**: Configurable strict host key checking
- **Secure file handling**: Proper error handling for missing files

## Error Handling

- Graceful handling of missing configuration files
- Detailed error messages for troubleshooting
- Fallback behaviors for optional configurations
- Proper logging of authentication attempts

## Examples

### Basic Setup

```bash
# Create user directory
mkdir -p /etc/sshpiper/users/alice

# Add upstream configuration
echo "backend.example.com:22" > /etc/sshpiper/users/alice/sshpiper_upstream
echo "alice" >> /etc/sshpiper/users/alice/sshpiper_upstream

# Add authorized key
ssh-keygen -t rsa -f /etc/sshpiper/users/alice/id_rsa
cp ~/.ssh/id_rsa.pub /etc/sshpiper/users/alice/authorized_keys
```

### Running the Plugin

```bash
sshpiperd --workingdir-root /etc/sshpiper/users
```

## Integration

The Working Directory plugin integrates seamlessly with the sshpiper ecosystem:

- **Consistent API**: Uses standard libplugin interfaces
- **Standardized helpers**: Leverages common functionality
- **Error handling**: Consistent error patterns
- **Logging**: Structured logging with context
- **Metrics**: Performance and usage tracking

## Best Practices

1. **Security**: Always validate file permissions and ownership
2. **Organization**: Use clear directory structure for user configurations
3. **Backup**: Regularly backup user configurations and keys
4. **Monitoring**: Monitor authentication attempts and failures
5. **Updates**: Keep SSH keys and configurations up to date

## Troubleshooting

### Common Issues

1. **Permission denied**: Check file permissions and ownership
2. **Authentication failed**: Verify authorized_keys format and content
3. **Connection refused**: Check upstream configuration and connectivity
4. **Host key verification failed**: Verify known_hosts configuration

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
sshpiperd --log-level debug --workingdir-root /etc/sshpiper/users
```

## Migration from Legacy

When migrating from older versions:

1. Update configuration files to use standard formats
2. Verify file permissions and ownership
3. Test authentication methods thoroughly
4. Update any custom scripts or automation
