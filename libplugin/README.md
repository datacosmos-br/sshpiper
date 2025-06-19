# SSHPiper LibPlugin - Standardized Plugin Framework

## Overview

The libplugin package provides a comprehensive, standardized framework for developing SSHPiper plugins with maximum code reuse, consistent patterns, and enterprise-grade observability.

## Core Components

### 1. Standard Helper Functions

The framework provides standardized helper functions for common operations:

#### Authentication Helpers

- `StandardTestPassword()` - Password authentication with htpasswd support
- `StandardAuthorizedKeys()` - SSH key loading with file/data/base64 support  
- `StandardTrustedUserCAKeys()` - CA key loading with environment variable expansion

#### Key Management Helpers

- `StandardKnownHosts()` - Known hosts loading with path resolution
- `StandardPrivateKey()` - Private key loading with error handling
- `StandardOverridePassword()` - Override password loading
- `StandardIgnoreHostKey()` - Host key ignoring logic

### 2. Super-Generic Infrastructure

#### StandardPluginBase

Provides core functionality for all plugins:

- **Logging**: Structured logging with consistent format
- **Metrics**: Performance and usage metrics collection
- **Validation**: Input validation with standard patterns
- **Error Handling**: Consistent error handling and wrapping

```go
base := libplugin.NewStandardPluginBase("myplugin", "1.0.0")
```

#### StandardPluginWrapper  

Complete plugin wrapper with standardized data structures:

- **Configuration**: Unified configuration structure
- **Operations**: Wrapped operations with metrics and logging
- **Validation**: Automatic configuration validation

```go
wrapper := libplugin.NewStandardPluginWrapper("myplugin", "1.0.0", "Description")
```

### 3. Standardized Data Structures

#### StandardAuthData

Common authentication data structure:

```go
type StandardAuthData struct {
    PasswordFile     string
    PasswordData     string
    PasswordBase64   string
    AuthorizedKeysFile     string
    AuthorizedKeysData     string
    AuthorizedKeysBase64   string
    TrustedUserCAKeysFile   string
    TrustedUserCAKeysData   string
    TrustedUserCAKeysBase64 string
}
```

#### StandardKeyData

Common key data structure:

```go
type StandardKeyData struct {
    KnownHostsFile     string
    KnownHostsData     string
    KnownHostsBase64   string
    PrivateKeyFile     string
    PrivateKeyData     string
    PrivateKeyBase64   string
    OverridePasswordFile   string
    OverridePasswordData   string
    OverridePasswordBase64 string
}
```

#### StandardConnectionData

Common connection data structure:

```go
type StandardConnectionData struct {
    Host              string
    Port              int32
    UserName          string
    IgnoreHostKey     bool
    Timeout           int
    MaxRetries        int
}
```

### 4. Observability Features

#### Metrics Collection

- **Counters**: Operation attempts, successes, errors
- **Timers**: Operation duration tracking
- **Custom Metrics**: Plugin-specific metrics

#### Structured Logging

- **JSON Format**: Machine-readable logs
- **Standard Fields**: Consistent field names across plugins
- **Context**: Rich context information for debugging

#### Error Handling

- **Wrapping**: Errors wrapped with operation context
- **Logging**: Automatic error logging with context
- **Metrics**: Error rate tracking

## Usage Patterns

### 1. Basic Plugin Structure

```go
type MyPluginWrapper struct {
    *libplugin.StandardPluginWrapper
    // Plugin-specific fields
}

func NewMyPluginWrapper() *MyPluginWrapper {
    wrapper := libplugin.NewStandardPluginWrapper("myplugin", "1.0.0", "My plugin")
    return &MyPluginWrapper{
        StandardPluginWrapper: wrapper,
    }
}
```

### 2. Implementing Authentication

```go
func (p *MyPluginWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
    var upstream *libplugin.Upstream
    err := p.LogOperation("test_password", func() error {
        result, err := libplugin.StandardTestPassword("", "/path/to/htpasswd", conn.User(), password)
        if err != nil {
            return p.ErrorHandler.WrapError("password_test", err)
        }
        
        if !result {
            return fmt.Errorf("authentication failed for user %s", conn.User())
        }
        
        upstream = &libplugin.Upstream{
            Host:          "target-host",
            Port:          22,
            UserName:      conn.User(),
            IgnoreHostKey: true,
            Auth: &libplugin.Upstream_Password{
                Password: &libplugin.UpstreamPasswordAuth{
                    Password: string(password),
                },
            },
        }
        
        return nil
    })
    
    return upstream, err
}
```

### 3. Configuration Validation

```go
func (p *MyPluginWrapper) ValidateConfig() error {
    return p.LogOperation("config_validation", func() error {
        if err := p.Validator.ValidateRequired("host", p.Config.ConnectionData.Host); err != nil {
            return err
        }
        
        if err := p.Validator.ValidateHostPort("target", fmt.Sprintf("%s:%d", 
            p.Config.ConnectionData.Host, p.Config.ConnectionData.Port)); err != nil {
            return err
        }
        
        return nil
    })
}
```

## Best Practices

### 1. Always Use LogOperation

Wrap all operations with `LogOperation` for consistent metrics and logging:

```go
err := p.LogOperation("operation_name", func() error {
    // Your operation logic here
    return nil
})
```

### 2. Use Standard Error Handling

Always wrap errors with context:

```go
if err != nil {
    return p.ErrorHandler.WrapError("operation_context", err)
}
```

### 3. Increment Metrics

Track important events:

```go
p.Metrics.IncrementCounter("auth_success")
p.Metrics.RecordDuration("auth_duration", duration)
```

### 4. Use Structured Logging

Provide rich context in logs:

```go
p.Logger.Info("operation completed", log.Fields{
    "user": conn.User(),
    "duration": duration,
    "result": "success",
})
```

### 5. Validate Configuration

Always validate configuration at startup:

```go
if err := config.Validate(); err != nil {
    return fmt.Errorf("invalid configuration: %w", err)
}
```

## Migration Guide

### From Legacy Plugins

1. **Replace Direct Helper Calls**:

   ```go
   // Old
   result := libplugin.TestPassword(...)
   
   // New  
   result, err := libplugin.StandardTestPassword(...)
   ```

2. **Use StandardPluginWrapper**:

   ```go
   // Old
   type MyPlugin struct {
       // Custom fields
   }
   
   // New
   type MyPlugin struct {
       *libplugin.StandardPluginWrapper
       // Custom fields
   }
   ```

3. **Wrap Operations**:

   ```go
   // Old
   func (p *MyPlugin) DoSomething() error {
       return someOperation()
   }
   
   // New
   func (p *MyPlugin) DoSomething() error {
       return p.LogOperation("do_something", func() error {
           return someOperation()
       })
   }
   ```

## Plugin Examples

See the following plugins for complete examples:

- `plugin/docker/` - Fully migrated to StandardPluginWrapper
- `plugin/kubernetes/` - Hybrid approach with Kubernetes-specific features
- `plugin/workingdir/` - File-based operations with standard helpers
- `plugin/yaml/` - Complex configuration with standard validation

## Metrics Reference

### Standard Counters

- `{operation}_attempts` - Number of operation attempts
- `{operation}_success` - Number of successful operations
- `{operation}_errors` - Number of failed operations

### Standard Timers

- `{operation}` - Duration of operation execution

### Authentication Metrics

- `password_auth_success` - Successful password authentications
- `publickey_auth_success` - Successful public key authentications
- `ca_auth_success` - Successful CA authentications

### File Operation Metrics

- `file_read_success` - Successful file reads
- `file_parse_success` - Successful file parsing
- `config_validation_success` - Successful configuration validations

## Configuration Schema

### Standard Plugin Configuration

```json
{
  "name": "plugin-name",
  "version": "1.0.0", 
  "description": "Plugin description",
  "auth_data": {
    "password_file": "/path/to/htpasswd",
    "authorized_keys_file": "/path/to/authorized_keys",
    "trusted_user_ca_keys_file": "/path/to/ca_keys"
  },
  "key_data": {
    "known_hosts_file": "/path/to/known_hosts",
    "private_key_file": "/path/to/private_key"
  },
  "connection_data": {
    "host": "target-host",
    "port": 22,
    "ignore_host_key": true
  },
  "plugin_specific": {
    "custom_field": "custom_value"
  }
}
```

## Troubleshooting

### Common Issues

1. **Configuration Validation Errors**
   - Check required fields are present
   - Verify file paths exist and are readable
   - Validate host:port format

2. **Authentication Failures**
   - Check file permissions
   - Verify htpasswd format
   - Validate SSH key format

3. **Metrics Not Appearing**
   - Ensure operations are wrapped with `LogOperation`
   - Check metric names follow standard patterns

### Debug Logging

Enable debug logging to see detailed operation information:

```go
p.Logger.Logger.SetLevel(log.DebugLevel)
```

## Performance Considerations

- **File Caching**: Standard helpers cache file contents
- **Lazy Loading**: Files loaded only when needed
- **Error Caching**: Failed file loads cached to avoid repeated attempts
- **Metrics Overhead**: Minimal overhead from metrics collection

## Security Considerations

- **File Permissions**: Validate file permissions before reading
- **Input Validation**: All inputs validated before processing
- **Error Information**: Errors don't leak sensitive information
- **Logging**: Sensitive data not logged in plain text 
