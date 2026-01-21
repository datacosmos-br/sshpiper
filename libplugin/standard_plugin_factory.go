package libplugin

import (
	"fmt"

	"github.com/urfave/cli/v2"
	log "github.com/sirupsen/logrus"
)

// PluginType represents the type of plugin implementation
type PluginType string

const (
	// PluginTypeSimpleAuth for plugins with basic authentication (fixed, simplemath, username-router)
	PluginTypeSimpleAuth PluginType = "simple_auth"
	
	// PluginTypeFileBased for plugins that use file-based configuration (workingdir, yaml)
	PluginTypeFileBased PluginType = "file_based"
	
	// PluginTypeAPIBased for plugins that use external APIs (kubernetes, remotecall)
	PluginTypeAPIBased PluginType = "api_based"
	
	// PluginTypeContainerBased for plugins that discover containers (docker)
	PluginTypeContainerBased PluginType = "container_based"
)

// StandardPluginInterface defines the simplified interface all plugins must implement
type StandardPluginInterface interface {
	// Plugin metadata
	GetName() string
	GetVersion() string
	GetDescription() string
	GetType() PluginType
	
	// Configuration
	GetFlags() []cli.Flag
	ParseConfig(c *cli.Context) (interface{}, error)
	ValidateConfig(config interface{}) error
	
	// Authentication - plugins implement based on their type
	TestPassword(config interface{}, conn ConnMetadata, password []byte) (*Upstream, error)
	AuthorizedKeys(config interface{}, conn ConnMetadata, key []byte) (*Upstream, error)
}

// StandardPluginFactory creates standardized plugins
type StandardPluginFactory struct {
	logger *StandardLogger
}

// NewStandardPluginFactory creates a new plugin factory
func NewStandardPluginFactory() *StandardPluginFactory {
	return &StandardPluginFactory{
		logger: NewStandardLogger("plugin_factory"),
	}
}

// CreatePlugin creates a standardized plugin configuration
func (spf *StandardPluginFactory) CreatePlugin(plugin StandardPluginInterface) *PluginEntrypoint {
	return &PluginEntrypoint{
		Name:         plugin.GetName(),
		Usage:        plugin.GetDescription(),
		Flags:        spf.getStandardFlags(plugin),
		CreateConfig: spf.createConfigFunc(plugin),
	}
}

// getStandardFlags returns standard flags plus plugin-specific flags
func (spf *StandardPluginFactory) getStandardFlags(plugin StandardPluginInterface) []cli.Flag {
	standardFlags := []cli.Flag{
		&cli.StringFlag{
			Name:  "working-dir",
			Usage: "Working directory for relative paths",
			Value: ".",
		},
		&cli.StringFlag{
			Name:  "log-level",
			Usage: "Log level (debug, info, warn, error)",
			Value: "info",
		},
	}
	
	// Add plugin-specific flags
	pluginFlags := plugin.GetFlags()
	return append(standardFlags, pluginFlags...)
}

// createConfigFunc creates the configuration function for the plugin
func (spf *StandardPluginFactory) createConfigFunc(plugin StandardPluginInterface) func(*cli.Context) (*PluginConfig, error) {
	return func(c *cli.Context) (*PluginConfig, error) {
		spf.logger.Info("creating plugin configuration", log.Fields{
			"plugin": plugin.GetName(),
			"type":   plugin.GetType(),
		})
		
		// Parse plugin-specific configuration
		pluginConfig, err := plugin.ParseConfig(c)
		if err != nil {
			return nil, fmt.Errorf("failed to parse plugin config: %w", err)
		}
		
		// Validate configuration
		if err := plugin.ValidateConfig(pluginConfig); err != nil {
			return nil, fmt.Errorf("configuration validation failed: %w", err)
		}
		
		// Set log level
		if logLevel := c.String("log-level"); logLevel != "" {
			if level, err := log.ParseLevel(logLevel); err == nil {
				log.SetLevel(level)
			}
		}
		
		// Create plugin configuration based on type
		switch plugin.GetType() {
		case PluginTypeSimpleAuth:
			return spf.createSimpleAuthConfig(plugin, pluginConfig)
		case PluginTypeFileBased, PluginTypeAPIBased, PluginTypeContainerBased:
			// These types need to integrate with existing skel framework
			// For now, we'll treat them as simple auth and let plugins handle the complexity
			return spf.createSimpleAuthConfig(plugin, pluginConfig)
		default:
			return nil, fmt.Errorf("unsupported plugin type: %s", plugin.GetType())
		}
	}
}

// createSimpleAuthConfig creates configuration for all plugin types using simple auth callbacks
func (spf *StandardPluginFactory) createSimpleAuthConfig(plugin StandardPluginInterface, config interface{}) (*PluginConfig, error) {
	spf.logger.Info("creating plugin configuration", log.Fields{
		"plugin": plugin.GetName(),
		"type":   config,
	})
	
	// Create standardized plugin configuration with validation and logging
	return &PluginConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Upstream, error) {
			// Use validation framework
			validation := NewStandardValidation(plugin.GetName())
			
			// Validate connection
			connResult := validation.ValidateValue("connection", conn)
			if !connResult.Valid {
				return nil, fmt.Errorf("connection validation failed: %v", connResult.Errors)
			}
			
			// Validate password
			passwordResult := validation.ValidateValue("password", password)
			if !passwordResult.Valid {
				return nil, fmt.Errorf("password validation failed: %v", passwordResult.Errors)
			}
			
			// Log warnings
			for _, warning := range append(connResult.Warnings, passwordResult.Warnings...) {
				spf.logger.Debug("validation warning: " + warning)
			}
			
			// Delegate to plugin implementation
			return plugin.TestPassword(config, conn, password)
		},
		PublicKeyCallback: func(conn ConnMetadata, key []byte) (*Upstream, error) {
			// Use validation framework
			validation := NewStandardValidation(plugin.GetName())
			
			// Validate connection
			connResult := validation.ValidateValue("connection", conn)
			if !connResult.Valid {
				return nil, fmt.Errorf("connection validation failed: %v", connResult.Errors)
			}
			
			// Validate SSH key
			keyResult := validation.ValidateValue("ssh_key", key)
			if !keyResult.Valid {
				return nil, fmt.Errorf("SSH key validation failed: %v", keyResult.Errors)
			}
			
			// Log warnings
			for _, warning := range append(connResult.Warnings, keyResult.Warnings...) {
				spf.logger.Debug("validation warning: " + warning)
			}
			
			// Delegate to plugin implementation
			return plugin.AuthorizedKeys(config, conn, key)
		},
	}, nil
}

// RunStandardPlugin is the main entry point for all standardized plugins
func RunStandardPlugin(plugin StandardPluginInterface) {
	factory := NewStandardPluginFactory()
	entrypoint := factory.CreatePlugin(plugin)
	RunPluginEntrypoint(entrypoint)
}

// Helper functions for common plugin patterns

// CreateSimplePasswordUpstream creates a password-based upstream with validation
func CreateSimplePasswordUpstream(pluginName, target, username, password string) (*Upstream, error) {
	// Validate target format
	host, portInt, err := SplitHostPortForSSH(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target format %s: %w", target, err)
	}
	
	// Use standardized upstream factory
	factory := NewStandardUpstreamFactory(pluginName)
	return factory.CreatePasswordUpstream(host, portInt, username, password, true)
}

// CreateValidatedConnection validates connection data using standard framework
func CreateValidatedConnection(pluginName string, conn ConnMetadata, host string, port int, username string) error {
	// Use connection validator for comprehensive validation
	validator := NewConnectionValidator(pluginName, ValidationLevelStandard)
	result := validator.ValidateConnection(conn, host, port, username)
	
	if !result.Valid {
		return fmt.Errorf("connection validation failed: %v", result.Errors)
	}
	
	// Log warnings if any
	logger := NewStandardLogger(pluginName)
	for _, warning := range result.Warnings {
		logger.Debug("connection validation warning: " + warning)
	}
	
	return nil
}

// LogPluginOperation logs plugin operations with metrics
func LogPluginOperation(pluginName, operation string, fn func() error) error {
	base := NewStandardPluginBase(pluginName, "1.0.0")
	return base.LogOperation(operation, fn)
}