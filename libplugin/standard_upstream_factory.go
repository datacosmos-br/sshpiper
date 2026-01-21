package libplugin

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// UpstreamAuthType represents different types of upstream authentication
type UpstreamAuthType string

const (
	UpstreamAuthNone         UpstreamAuthType = "none"
	UpstreamAuthPassword     UpstreamAuthType = "password"
	UpstreamAuthPrivateKey   UpstreamAuthType = "private_key"
	UpstreamAuthRemoteSigner UpstreamAuthType = "remote_signer"
)

// StandardUpstreamConfig represents configuration for creating upstreams
type StandardUpstreamConfig struct {
	// Connection details
	Host     string `json:"host"`
	Port     int32  `json:"port"`
	UserName string `json:"user_name"`
	
	// Authentication configuration
	AuthType      UpstreamAuthType `json:"auth_type"`
	Password      string          `json:"password,omitempty"`
	PrivateKey    []byte          `json:"private_key,omitempty"`
	PublicKey     []byte          `json:"public_key,omitempty"`
	
	// Connection options
	IgnoreHostKey     bool `json:"ignore_host_key"`
	ConnectionTimeout int  `json:"connection_timeout,omitempty"`
	MaxRetries        int  `json:"max_retries,omitempty"`
}

// StandardUpstreamFactory creates standardized upstream connections
type StandardUpstreamFactory struct {
	logger    *StandardLogger
	validator *StandardValidator
}

// NewStandardUpstreamFactory creates a new upstream factory
func NewStandardUpstreamFactory(pluginName string) *StandardUpstreamFactory {
	return &StandardUpstreamFactory{
		logger:    NewStandardLogger(fmt.Sprintf("%s_upstream_factory", pluginName)),
		validator: &StandardValidator{},
	}
}

// CreateUpstream creates a standardized upstream connection
func (suf *StandardUpstreamFactory) CreateUpstream(config StandardUpstreamConfig) (*Upstream, error) {
	// Validate configuration
	if err := suf.validateConfig(config); err != nil {
		suf.logger.Error("upstream configuration validation failed", err, log.Fields{
			"host":      config.Host,
			"port":      config.Port,
			"user":      config.UserName,
			"auth_type": config.AuthType,
		})
		return nil, fmt.Errorf("upstream configuration validation failed: %w", err)
	}
	
	suf.logger.Debug("creating upstream connection", log.Fields{
		"host":      config.Host,
		"port":      config.Port,
		"user":      config.UserName,
		"auth_type": config.AuthType,
	})
	
	// Create base upstream
	upstream := &Upstream{
		Host:          config.Host,
		Port:          config.Port,
		UserName:      config.UserName,
		IgnoreHostKey: config.IgnoreHostKey,
	}
	
	// Set authentication based on type
	switch config.AuthType {
	case UpstreamAuthNone:
		upstream.Auth = suf.createNoneAuth(config)
	case UpstreamAuthPassword:
		upstream.Auth = suf.createPasswordAuth(config)
	case UpstreamAuthPrivateKey:
		upstream.Auth = suf.createPrivateKeyAuth(config)
	case UpstreamAuthRemoteSigner:
		upstream.Auth = suf.createRemoteSignerAuth(config)
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", config.AuthType)
	}
	
	suf.logger.Info("upstream connection created successfully", log.Fields{
		"host":           config.Host,
		"port":           config.Port,
		"user":           config.UserName,
		"auth_type":      config.AuthType,
		"ignore_hostkey": config.IgnoreHostKey,
	})
	
	return upstream, nil
}

// CreatePasswordUpstream creates an upstream with password authentication
func (suf *StandardUpstreamFactory) CreatePasswordUpstream(host string, port int, user, password string, ignoreHostKey bool) (*Upstream, error) {
	config := StandardUpstreamConfig{
		Host:          host,
		Port:          int32(port),
		UserName:      user,
		AuthType:      UpstreamAuthPassword,
		Password:      password,
		IgnoreHostKey: ignoreHostKey,
	}
	
	return suf.CreateUpstream(config)
}

// CreatePrivateKeyUpstream creates an upstream with private key authentication
func (suf *StandardUpstreamFactory) CreatePrivateKeyUpstream(host string, port int, user string, privateKey []byte, ignoreHostKey bool) (*Upstream, error) {
	config := StandardUpstreamConfig{
		Host:          host,
		Port:          int32(port),
		UserName:      user,
		AuthType:      UpstreamAuthPrivateKey,
		PrivateKey:    privateKey,
		IgnoreHostKey: ignoreHostKey,
	}
	
	return suf.CreateUpstream(config)
}

// CreateNoneUpstream creates an upstream with no authentication
func (suf *StandardUpstreamFactory) CreateNoneUpstream(host string, port int, user string, ignoreHostKey bool) (*Upstream, error) {
	config := StandardUpstreamConfig{
		Host:          host,
		Port:          int32(port),
		UserName:      user,
		AuthType:      UpstreamAuthNone,
		IgnoreHostKey: ignoreHostKey,
	}
	
	return suf.CreateUpstream(config)
}

// CreateFromHostString creates an upstream from host string (host:port format)
func (suf *StandardUpstreamFactory) CreateFromHostString(hostString, user, password string, ignoreHostKey bool) (*Upstream, error) {
	host, portInt, err := SplitHostPortForSSH(hostString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host string %s: %w", hostString, err)
	}
	
	return suf.CreatePasswordUpstream(host, portInt, user, password, ignoreHostKey)
}

// CreateFromConnectionData creates upstream from standard connection data
func (suf *StandardUpstreamFactory) CreateFromConnectionData(connData StandardConnectionData, authType UpstreamAuthType, authData interface{}) (*Upstream, error) {
	config := StandardUpstreamConfig{
		Host:              connData.Host,
		Port:              connData.Port,
		UserName:          connData.UserName,
		AuthType:          authType,
		IgnoreHostKey:     connData.IgnoreHostKey,
		ConnectionTimeout: connData.Timeout,
		MaxRetries:        connData.MaxRetries,
	}
	
	// Set authentication data based on type
	switch authType {
	case UpstreamAuthPassword:
		if password, ok := authData.(string); ok {
			config.Password = password
		} else {
			return nil, fmt.Errorf("password authentication requires string auth data")
		}
	case UpstreamAuthPrivateKey:
		if privateKey, ok := authData.([]byte); ok {
			config.PrivateKey = privateKey
		} else {
			return nil, fmt.Errorf("private key authentication requires []byte auth data")
		}
	}
	
	return suf.CreateUpstream(config)
}

// validateConfig validates upstream configuration
func (suf *StandardUpstreamFactory) validateConfig(config StandardUpstreamConfig) error {
	// Validate required fields
	if err := suf.validator.ValidateRequired("host", config.Host); err != nil {
		return err
	}
	if err := suf.validator.ValidateRequired("user_name", config.UserName); err != nil {
		return err
	}
	
	// Validate port range
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", config.Port)
	}
	
	// Validate authentication type and corresponding data
	switch config.AuthType {
	case UpstreamAuthNone:
		// None auth doesn't require additional data
	case UpstreamAuthPassword:
		if config.Password == "" {
			return fmt.Errorf("password is required for password authentication")
		}
	case UpstreamAuthPrivateKey:
		if len(config.PrivateKey) == 0 {
			return fmt.Errorf("private key is required for private key authentication")
		}
	case UpstreamAuthRemoteSigner:
		// Remote signer auth doesn't require additional data
	default:
		return fmt.Errorf("unsupported authentication type: %s", config.AuthType)
	}
	
	return nil
}

// createNoneAuth creates no authentication
func (suf *StandardUpstreamFactory) createNoneAuth(config StandardUpstreamConfig) isUpstream_Auth {
	return &Upstream_None{
		None: &UpstreamNoneAuth{},
	}
}

// createPasswordAuth creates password authentication
func (suf *StandardUpstreamFactory) createPasswordAuth(config StandardUpstreamConfig) isUpstream_Auth {
	return &Upstream_Password{
		Password: &UpstreamPasswordAuth{
			Password: config.Password,
		},
	}
}

// createPrivateKeyAuth creates private key authentication
func (suf *StandardUpstreamFactory) createPrivateKeyAuth(config StandardUpstreamConfig) isUpstream_Auth {
	auth := &UpstreamPrivateKeyAuth{
		PrivateKey: config.PrivateKey,
	}
	
	// Add CA public key if provided
	if len(config.PublicKey) > 0 {
		auth.CaPublicKey = config.PublicKey
	}
	
	return &Upstream_PrivateKey{
		PrivateKey: auth,
	}
}

// createRemoteSignerAuth creates remote signer authentication
func (suf *StandardUpstreamFactory) createRemoteSignerAuth(config StandardUpstreamConfig) isUpstream_Auth {
	return &Upstream_RemoteSigner{
		RemoteSigner: &UpstreamRemoteSignerAuth{},
	}
}

// StandardUpstreamBuilder provides a builder pattern for creating upstreams
type StandardUpstreamBuilder struct {
	factory *StandardUpstreamFactory
	config  StandardUpstreamConfig
}

// NewUpstreamBuilder creates a new upstream builder
func NewUpstreamBuilder(pluginName string) *StandardUpstreamBuilder {
	return &StandardUpstreamBuilder{
		factory: NewStandardUpstreamFactory(pluginName),
		config:  StandardUpstreamConfig{},
	}
}

// Host sets the host
func (sub *StandardUpstreamBuilder) Host(host string) *StandardUpstreamBuilder {
	sub.config.Host = host
	return sub
}

// Port sets the port
func (sub *StandardUpstreamBuilder) Port(port int) *StandardUpstreamBuilder {
	sub.config.Port = int32(port)
	return sub
}

// User sets the username
func (sub *StandardUpstreamBuilder) User(user string) *StandardUpstreamBuilder {
	sub.config.UserName = user
	return sub
}

// PasswordAuth sets password authentication
func (sub *StandardUpstreamBuilder) PasswordAuth(password string) *StandardUpstreamBuilder {
	sub.config.AuthType = UpstreamAuthPassword
	sub.config.Password = password
	return sub
}

// PrivateKeyAuth sets private key authentication
func (sub *StandardUpstreamBuilder) PrivateKeyAuth(privateKey []byte, publicKey []byte) *StandardUpstreamBuilder {
	sub.config.AuthType = UpstreamAuthPrivateKey
	sub.config.PrivateKey = privateKey
	sub.config.PublicKey = publicKey
	return sub
}

// NoneAuth sets no authentication
func (sub *StandardUpstreamBuilder) NoneAuth() *StandardUpstreamBuilder {
	sub.config.AuthType = UpstreamAuthNone
	return sub
}

// RemoteSignerAuth sets remote signer authentication
func (sub *StandardUpstreamBuilder) RemoteSignerAuth() *StandardUpstreamBuilder {
	sub.config.AuthType = UpstreamAuthRemoteSigner
	return sub
}

// IgnoreHostKey sets host key validation behavior
func (sub *StandardUpstreamBuilder) IgnoreHostKey(ignore bool) *StandardUpstreamBuilder {
	sub.config.IgnoreHostKey = ignore
	return sub
}


// Timeout sets connection timeout
func (sub *StandardUpstreamBuilder) Timeout(timeout int) *StandardUpstreamBuilder {
	sub.config.ConnectionTimeout = timeout
	return sub
}

// MaxRetries sets maximum retry attempts
func (sub *StandardUpstreamBuilder) MaxRetries(retries int) *StandardUpstreamBuilder {
	sub.config.MaxRetries = retries
	return sub
}


// Build creates the upstream connection
func (sub *StandardUpstreamBuilder) Build() (*Upstream, error) {
	return sub.factory.CreateUpstream(sub.config)
}

// Convenience functions for common patterns

// CreateSimplePasswordUpstreamStandard creates a simple password-based upstream
func CreateSimplePasswordUpstreamStandard(host string, port int, user, password string) (*Upstream, error) {
	factory := NewStandardUpstreamFactory("simple")
	return factory.CreatePasswordUpstream(host, port, user, password, true)
}

// CreateSecurePasswordUpstream creates a password-based upstream with host key validation
func CreateSecurePasswordUpstream(host string, port int, user, password string) (*Upstream, error) {
	builder := NewUpstreamBuilder("secure")
	return builder.
		Host(host).
		Port(port).
		User(user).
		PasswordAuth(password).
		IgnoreHostKey(false).
		Build()
}

// CreatePrivateKeyUpstream creates a private key-based upstream
func CreatePrivateKeyUpstream(host string, port int, user string, privateKey []byte) (*Upstream, error) {
	factory := NewStandardUpstreamFactory("key_auth")
	return factory.CreatePrivateKeyUpstream(host, port, user, privateKey, true)
}

// ParseHostPortUser parses a connection string in format "user@host:port"
func ParseHostPortUser(connectionString string) (host string, port int, user string, err error) {
	// Handle user@host:port format
	if strings.Contains(connectionString, "@") {
		parts := strings.SplitN(connectionString, "@", 2)
		if len(parts) != 2 {
			return "", 0, "", fmt.Errorf("invalid connection string format: %s", connectionString)
		}
		user = parts[0]
		connectionString = parts[1]
	}
	
	// Parse host:port
	host, port, err = SplitHostPortForSSH(connectionString)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to parse host:port from %s: %w", connectionString, err)
	}
	
	return host, port, user, nil
}

// CreateUpstreamFromConnectionString creates upstream from connection string
func CreateUpstreamFromConnectionString(connectionString, password string, ignoreHostKey bool) (*Upstream, error) {
	host, port, user, err := ParseHostPortUser(connectionString)
	if err != nil {
		return nil, err
	}
	
	factory := NewStandardUpstreamFactory("connection_string")
	return factory.CreatePasswordUpstream(host, port, user, password, ignoreHostKey)
}