package libplugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	log "github.com/sirupsen/logrus"
)

// DeclarativeConfigManager manages YAML-based plugin configurations
type DeclarativeConfigManager struct {
	configPath    string
	schemaPath    string
	logger        *StandardLogger
	validator     *ConfigValidator
	templates     map[string]*ConfigTemplate
	environments  map[string]*Environment
}

// SSHPiperConfig represents the complete SSHPiper configuration
type SSHPiperConfig struct {
	// Global configuration
	APIVersion string                 `yaml:"apiVersion" json:"apiVersion"`
	Kind       string                 `yaml:"kind" json:"kind"`
	Metadata   ConfigMetadata         `yaml:"metadata" json:"metadata"`
	Spec       SSHPiperSpec          `yaml:"spec" json:"spec"`
	
	// Status (managed by system)
	Status     SSHPiperStatus        `yaml:"status,omitempty" json:"status,omitempty"`
}

// ConfigMetadata contains metadata about the configuration
type ConfigMetadata struct {
	Name        string            `yaml:"name" json:"name"`
	Namespace   string            `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
	CreatedAt   time.Time         `yaml:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt   time.Time         `yaml:"updatedAt,omitempty" json:"updatedAt,omitempty"`
}

// SSHPiperSpec defines the desired state of SSHPiper
type SSHPiperSpec struct {
	// Global settings
	Global      GlobalConfig          `yaml:"global" json:"global"`
	
	// Security settings
	Security    SecurityConfig        `yaml:"security" json:"security"`
	
	// Observability settings
	Observability ObservabilityConfig `yaml:"observability" json:"observability"`
	
	// Plugin configurations
	Plugins     []PluginSpec         `yaml:"plugins" json:"plugins"`
	
	// Route definitions
	Routes      []RouteSpec          `yaml:"routes" json:"routes"`
	
	// Environment-specific overrides
	Environments map[string]EnvironmentOverride `yaml:"environments,omitempty" json:"environments,omitempty"`
}

// GlobalConfig contains global SSHPiper settings
type GlobalConfig struct {
	// Server configuration
	Server      ServerConfig          `yaml:"server" json:"server"`
	
	// Connection settings
	Connection  ConnectionConfig      `yaml:"connection" json:"connection"`
	
	// Performance settings
	Performance PerformanceConfig     `yaml:"performance" json:"performance"`
	
	// Feature flags
	Features    FeatureFlags          `yaml:"features" json:"features"`
}

// ServerConfig defines server-level settings
type ServerConfig struct {
	ListenAddr     string        `yaml:"listenAddr" json:"listenAddr"`
	ListenPort     int           `yaml:"listenPort" json:"listenPort"`
	HostKey        string        `yaml:"hostKey" json:"hostKey"`
	HostKeyPath    string        `yaml:"hostKeyPath,omitempty" json:"hostKeyPath,omitempty"`
	Banner         string        `yaml:"banner,omitempty" json:"banner,omitempty"`
	BannerFile     string        `yaml:"bannerFile,omitempty" json:"bannerFile,omitempty"`
	MaxConnections int           `yaml:"maxConnections" json:"maxConnections"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	KeepAlive      time.Duration `yaml:"keepAlive" json:"keepAlive"`
}

// ConnectionConfig defines connection-level settings
type ConnectionConfig struct {
	MaxRetries      int           `yaml:"maxRetries" json:"maxRetries"`
	RetryDelay      time.Duration `yaml:"retryDelay" json:"retryDelay"`
	ConnectTimeout  time.Duration `yaml:"connectTimeout" json:"connectTimeout"`
	HandshakeTimeout time.Duration `yaml:"handshakeTimeout" json:"handshakeTimeout"`
	IdleTimeout     time.Duration `yaml:"idleTimeout" json:"idleTimeout"`
	MaxChannels     int           `yaml:"maxChannels" json:"maxChannels"`
	BufferSize      int           `yaml:"bufferSize" json:"bufferSize"`
}

// PerformanceConfig defines performance-related settings
type PerformanceConfig struct {
	ConnectionPooling    bool          `yaml:"connectionPooling" json:"connectionPooling"`
	PoolSize            int           `yaml:"poolSize" json:"poolSize"`
	PoolMaxIdle         time.Duration `yaml:"poolMaxIdle" json:"poolMaxIdle"`
	CompressionEnabled  bool          `yaml:"compressionEnabled" json:"compressionEnabled"`
	CompressionLevel    int           `yaml:"compressionLevel" json:"compressionLevel"`
	TCPNoDelay          bool          `yaml:"tcpNoDelay" json:"tcpNoDelay"`
	TCPKeepAlive        bool          `yaml:"tcpKeepAlive" json:"tcpKeepAlive"`
}

// FeatureFlags enables/disables optional features
type FeatureFlags struct {
	HotReload           bool `yaml:"hotReload" json:"hotReload"`
	PluginDiscovery     bool `yaml:"pluginDiscovery" json:"pluginDiscovery"`
	AdvancedMetrics     bool `yaml:"advancedMetrics" json:"advancedMetrics"`
	DistributedTracing  bool `yaml:"distributedTracing" json:"distributedTracing"`
	AuditLogging        bool `yaml:"auditLogging" json:"auditLogging"`
	RateLimiting        bool `yaml:"rateLimiting" json:"rateLimiting"`
	FailureBanning      bool `yaml:"failureBanning" json:"failureBanning"`
}

// SecurityConfig defines security settings
type SecurityConfig struct {
	// Authentication settings
	Authentication AuthenticationConfig `yaml:"authentication" json:"authentication"`
	
	// Authorization settings
	Authorization  AuthorizationConfig  `yaml:"authorization" json:"authorization"`
	
	// Rate limiting
	RateLimit      RateLimitConfig      `yaml:"rateLimit" json:"rateLimit"`
	
	// Failure banning
	FailureBan     FailureBanConfig     `yaml:"failureBan" json:"failureBan"`
	
	// TLS settings
	TLS            TLSConfig           `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// AuthenticationConfig defines authentication settings
type AuthenticationConfig struct {
	RequiredMethods []string          `yaml:"requiredMethods" json:"requiredMethods"`
	AllowedUsers    []string          `yaml:"allowedUsers,omitempty" json:"allowedUsers,omitempty"`
	DeniedUsers     []string          `yaml:"deniedUsers,omitempty" json:"deniedUsers,omitempty"`
	MaxAuthTries    int               `yaml:"maxAuthTries" json:"maxAuthTries"`
	AuthTimeout     time.Duration     `yaml:"authTimeout" json:"authTimeout"`
	PublicKeyAuth   PublicKeyAuthConfig `yaml:"publicKeyAuth" json:"publicKeyAuth"`
	PasswordAuth    PasswordAuthConfig  `yaml:"passwordAuth" json:"passwordAuth"`
}

// PublicKeyAuthConfig defines public key authentication settings
type PublicKeyAuthConfig struct {
	Enabled             bool     `yaml:"enabled" json:"enabled"`
	RequiredKeyTypes    []string `yaml:"requiredKeyTypes,omitempty" json:"requiredKeyTypes,omitempty"`
	MinKeySize          int      `yaml:"minKeySize" json:"minKeySize"`
	AllowedAlgorithms   []string `yaml:"allowedAlgorithms,omitempty" json:"allowedAlgorithms,omitempty"`
	CertificateAuth     bool     `yaml:"certificateAuth" json:"certificateAuth"`
}

// PasswordAuthConfig defines password authentication settings
type PasswordAuthConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	MinLength       int           `yaml:"minLength" json:"minLength"`
	RequireComplex  bool          `yaml:"requireComplex" json:"requireComplex"`
	MaxAge          time.Duration `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`
	PreventReuse    int           `yaml:"preventReuse,omitempty" json:"preventReuse,omitempty"`
}

// AuthorizationConfig defines authorization settings
type AuthorizationConfig struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	DefaultPolicy   string   `yaml:"defaultPolicy" json:"defaultPolicy"`
	Policies        []string `yaml:"policies,omitempty" json:"policies,omitempty"`
	RoleBasedAccess bool     `yaml:"roleBasedAccess" json:"roleBasedAccess"`
	AuditEnabled    bool     `yaml:"auditEnabled" json:"auditEnabled"`
}

// RateLimitConfig defines rate limiting settings
type RateLimitConfig struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	ConnectionsPerIP  int           `yaml:"connectionsPerIP" json:"connectionsPerIP"`
	ConnectionsPerUser int          `yaml:"connectionsPerUser" json:"connectionsPerUser"`
	WindowSize        time.Duration `yaml:"windowSize" json:"windowSize"`
	BurstSize         int           `yaml:"burstSize" json:"burstSize"`
	WhitelistedIPs    []string      `yaml:"whitelistedIPs,omitempty" json:"whitelistedIPs,omitempty"`
}

// FailureBanConfig defines failure banning settings
type FailureBanConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	MaxFailures     int           `yaml:"maxFailures" json:"maxFailures"`
	BanDuration     time.Duration `yaml:"banDuration" json:"banDuration"`
	WindowSize      time.Duration `yaml:"windowSize" json:"windowSize"`
	WhitelistedIPs  []string      `yaml:"whitelistedIPs,omitempty" json:"whitelistedIPs,omitempty"`
	PersistentBans  bool          `yaml:"persistentBans" json:"persistentBans"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	CertFile    string   `yaml:"certFile" json:"certFile"`
	KeyFile     string   `yaml:"keyFile" json:"keyFile"`
	CAFile      string   `yaml:"caFile,omitempty" json:"caFile,omitempty"`
	MinVersion  string   `yaml:"minVersion" json:"minVersion"`
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`
}

// ObservabilityConfig defines observability settings
type ObservabilityConfig struct {
	// Global settings
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	ServiceName     string `yaml:"service_name" json:"service_name"`
	ServiceVersion  string `yaml:"service_version" json:"service_version"`
	Environment     string `yaml:"environment" json:"environment"`
	
	// Logging configuration
	Logging    LoggingConfig    `yaml:"logging" json:"logging"`
	
	// Metrics configuration
	Metrics    MetricsConfig    `yaml:"metrics" json:"metrics"`
	
	// Tracing configuration
	Tracing    TracingConfig    `yaml:"tracing" json:"tracing"`
	
	// Health check configuration
	HealthCheck HealthCheckConfig `yaml:"healthCheck" json:"healthCheck"`
	
	// Export configuration
	Exporters       ExportersConfig `yaml:"exporters" json:"exporters"`
}

// LoggingConfig defines logging settings
type LoggingConfig struct {
	Level      string            `yaml:"level" json:"level"`
	Format     string            `yaml:"format" json:"format"`
	Output     string            `yaml:"output" json:"output"`
	File       string            `yaml:"file,omitempty" json:"file,omitempty"`
	MaxSize    int               `yaml:"maxSize" json:"maxSize"`
	MaxAge     int               `yaml:"maxAge" json:"maxAge"`
	MaxBackups int               `yaml:"maxBackups" json:"maxBackups"`
	Compress   bool              `yaml:"compress" json:"compress"`
	Fields     map[string]string `yaml:"fields,omitempty" json:"fields,omitempty"`
	TraceID         bool   `yaml:"trace_id" json:"trace_id"`
	SpanID          bool   `yaml:"span_id" json:"span_id"`
	ContextFields   bool   `yaml:"context_fields" json:"context_fields"`
}

// MetricsConfig defines metrics settings
type MetricsConfig struct {
	Enabled         bool              `yaml:"enabled" json:"enabled"`
	Port            int               `yaml:"port" json:"port"`
	Path            string            `yaml:"path" json:"path"`
	Namespace       string            `yaml:"namespace" json:"namespace"`
	Labels          map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Collectors      []string          `yaml:"collectors,omitempty" json:"collectors,omitempty"`
	Interval        time.Duration     `yaml:"interval" json:"interval"`
	SystemMetrics   bool              `yaml:"system_metrics" json:"system_metrics"`
	PluginMetrics   bool              `yaml:"plugin_metrics" json:"plugin_metrics"`
	SecurityMetrics bool              `yaml:"security_metrics" json:"security_metrics"`
}

// TracingConfig defines distributed tracing settings
type TracingConfig struct {
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	ServiceName string            `yaml:"serviceName" json:"serviceName"`
	Endpoint    string            `yaml:"endpoint" json:"endpoint"`
	SampleRate  float64           `yaml:"sampleRate" json:"sampleRate"`
	Headers     map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	BatchSize   int               `yaml:"batchSize" json:"batchSize"`
	Timeout     time.Duration     `yaml:"timeout" json:"timeout"`
}

// PluginSpec defines a plugin configuration
type PluginSpec struct {
	// Plugin identification
	Name        string            `yaml:"name" json:"name"`
	Version     string            `yaml:"version,omitempty" json:"version,omitempty"`
	Type        PluginType        `yaml:"type" json:"type"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	
	// Loading configuration
	LoadOrder   int               `yaml:"loadOrder,omitempty" json:"loadOrder,omitempty"`
	HotReload   bool              `yaml:"hotReload" json:"hotReload"`
	
	// Dependencies
	Dependencies []string         `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`
	Conflicts    []string         `yaml:"conflicts,omitempty" json:"conflicts,omitempty"`
	
	// Resource limits
	Resources   PluginResources   `yaml:"resources,omitempty" json:"resources,omitempty"`
	
	// Health monitoring
	HealthCheck HealthCheckConfig `yaml:"healthCheck,omitempty" json:"healthCheck,omitempty"`
	
	// Plugin-specific configuration
	Config      map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	
	// Security settings
	Security    PluginSecurity    `yaml:"security,omitempty" json:"security,omitempty"`
	
	// Template reference
	Template    string            `yaml:"template,omitempty" json:"template,omitempty"`
}

// RouteSpec defines a routing rule
type RouteSpec struct {
	// Route identification
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	Priority    int               `yaml:"priority,omitempty" json:"priority,omitempty"`
	
	// Matching criteria
	Match       RouteMatch        `yaml:"match" json:"match"`
	
	// Target specification
	Target      RouteTarget       `yaml:"target" json:"target"`
	
	// Route-specific security
	Security    RouteSecurity     `yaml:"security,omitempty" json:"security,omitempty"`
	
	// Load balancing
	LoadBalancing LoadBalancingConfig `yaml:"loadBalancing,omitempty" json:"loadBalancing,omitempty"`
	
	// Retry policy
	RetryPolicy RetryPolicyConfig `yaml:"retryPolicy,omitempty" json:"retryPolicy,omitempty"`
}

// RouteMatch defines matching criteria for routes
type RouteMatch struct {
	Users       []string          `yaml:"users,omitempty" json:"users,omitempty"`
	UserPattern string            `yaml:"userPattern,omitempty" json:"userPattern,omitempty"`
	SourceIPs   []string          `yaml:"sourceIPs,omitempty" json:"sourceIPs,omitempty"`
	SourceCIDRs []string          `yaml:"sourceCIDRs,omitempty" json:"sourceCIDRs,omitempty"`
	TimeRanges  []TimeRange       `yaml:"timeRanges,omitempty" json:"timeRanges,omitempty"`
	Plugins     []string          `yaml:"plugins,omitempty" json:"plugins,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// TimeRange defines a time-based matching criteria
type TimeRange struct {
	Start    string   `yaml:"start" json:"start"`
	End      string   `yaml:"end" json:"end"`
	Days     []string `yaml:"days,omitempty" json:"days,omitempty"`
	TimeZone string   `yaml:"timeZone,omitempty" json:"timeZone,omitempty"`
}

// RouteTarget defines the target for a route
type RouteTarget struct {
	Type        string            `yaml:"type" json:"type"`
	Plugin      string            `yaml:"plugin,omitempty" json:"plugin,omitempty"`
	Hosts       []string          `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Config      map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
}

// RouteSecurity defines security settings for a route
type RouteSecurity struct {
	AllowedMethods []string          `yaml:"allowedMethods,omitempty" json:"allowedMethods,omitempty"`
	RequireAuth    bool              `yaml:"requireAuth" json:"requireAuth"`
	RateLimit      *RateLimitConfig  `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	MaxSessions    int               `yaml:"maxSessions,omitempty" json:"maxSessions,omitempty"`
	SessionTimeout time.Duration     `yaml:"sessionTimeout,omitempty" json:"sessionTimeout,omitempty"`
}

// LoadBalancingConfig defines load balancing settings
type LoadBalancingConfig struct {
	Strategy    string            `yaml:"strategy" json:"strategy"`
	HealthCheck bool              `yaml:"healthCheck" json:"healthCheck"`
	Weights     map[string]int    `yaml:"weights,omitempty" json:"weights,omitempty"`
	StickySession bool            `yaml:"stickySession" json:"stickySession"`
}

// RetryPolicyConfig defines retry policy settings
type RetryPolicyConfig struct {
	MaxRetries    int           `yaml:"maxRetries" json:"maxRetries"`
	InitialDelay  time.Duration `yaml:"initialDelay" json:"initialDelay"`
	MaxDelay      time.Duration `yaml:"maxDelay" json:"maxDelay"`
	BackoffFactor float64       `yaml:"backoffFactor" json:"backoffFactor"`
	RetryConditions []string    `yaml:"retryConditions,omitempty" json:"retryConditions,omitempty"`
}

// EnvironmentOverride defines environment-specific configuration overrides
type EnvironmentOverride struct {
	Global   *GlobalConfig `yaml:"global,omitempty" json:"global,omitempty"`
	Security *SecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`
	Plugins  []PluginOverride `yaml:"plugins,omitempty" json:"plugins,omitempty"`
	Routes   []RouteOverride  `yaml:"routes,omitempty" json:"routes,omitempty"`
}

// PluginOverride defines plugin-specific overrides
type PluginOverride struct {
	Name    string                 `yaml:"name" json:"name"`
	Enabled *bool                  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Config  map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
}

// RouteOverride defines route-specific overrides
type RouteOverride struct {
	Name    string                 `yaml:"name" json:"name"`
	Enabled *bool                  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Target  *RouteTarget           `yaml:"target,omitempty" json:"target,omitempty"`
}

// SSHPiperStatus represents the current status of the system
type SSHPiperStatus struct {
	Phase        string                 `yaml:"phase" json:"phase"`
	Message      string                 `yaml:"message,omitempty" json:"message,omitempty"`
	Conditions   []StatusCondition      `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	PluginStatus map[string]PluginStatus `yaml:"pluginStatus,omitempty" json:"pluginStatus,omitempty"`
	RouteStatus  map[string]RouteStatus  `yaml:"routeStatus,omitempty" json:"routeStatus,omitempty"`
	LastUpdated  time.Time              `yaml:"lastUpdated" json:"lastUpdated"`
}

// StatusCondition represents a condition of the system
type StatusCondition struct {
	Type               string    `yaml:"type" json:"type"`
	Status             string    `yaml:"status" json:"status"`
	LastTransitionTime time.Time `yaml:"lastTransitionTime" json:"lastTransitionTime"`
	Reason             string    `yaml:"reason,omitempty" json:"reason,omitempty"`
	Message            string    `yaml:"message,omitempty" json:"message,omitempty"`
}

// RouteStatus represents the status of a route
type RouteStatus struct {
	Active      bool      `yaml:"active" json:"active"`
	LastMatched time.Time `yaml:"lastMatched,omitempty" json:"lastMatched,omitempty"`
	MatchCount  int64     `yaml:"matchCount" json:"matchCount"`
	ErrorCount  int64     `yaml:"errorCount" json:"errorCount"`
	LastError   string    `yaml:"lastError,omitempty" json:"lastError,omitempty"`
}

// ConfigTemplate defines a reusable configuration template
type ConfigTemplate struct {
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Version     string                 `yaml:"version" json:"version"`
	Parameters  []TemplateParameter    `yaml:"parameters" json:"parameters"`
	Template    map[string]interface{} `yaml:"template" json:"template"`
}

// TemplateParameter defines a template parameter
type TemplateParameter struct {
	Name         string      `yaml:"name" json:"name"`
	Description  string      `yaml:"description" json:"description"`
	Type         string      `yaml:"type" json:"type"`
	Default      interface{} `yaml:"default,omitempty" json:"default,omitempty"`
	Required     bool        `yaml:"required" json:"required"`
	Validation   string      `yaml:"validation,omitempty" json:"validation,omitempty"`
	Options      []string    `yaml:"options,omitempty" json:"options,omitempty"`
}

// Environment defines an environment configuration
type Environment struct {
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Variables   map[string]string      `yaml:"variables" json:"variables"`
	Secrets     map[string]string      `yaml:"secrets" json:"secrets"`
	Overrides   map[string]interface{} `yaml:"overrides" json:"overrides"`
}

// ConfigValidator validates configuration files
type ConfigValidator struct {
	schemas map[string]interface{}
	logger  *StandardLogger
}

// NewDeclarativeConfigManager creates a new declarative config manager
func NewDeclarativeConfigManager(configPath, schemaPath string) (*DeclarativeConfigManager, error) {
	logger := NewStandardLogger("declarative_config")
	
	validator := &ConfigValidator{
		schemas: make(map[string]interface{}),
		logger:  logger,
	}
	
	dcm := &DeclarativeConfigManager{
		configPath:   configPath,
		schemaPath:   schemaPath,
		logger:       logger,
		validator:    validator,
		templates:    make(map[string]*ConfigTemplate),
		environments: make(map[string]*Environment),
	}
	
	logger.Info("declarative config manager created", log.Fields{
		"config_path": configPath,
		"schema_path": schemaPath,
	})
	
	return dcm, nil
}

// LoadConfiguration loads and validates a configuration file
func (dcm *DeclarativeConfigManager) LoadConfiguration(path string) (*SSHPiperConfig, error) {
	dcm.logger.Info("loading configuration", log.Fields{
		"path": path,
	})
	
	// Read configuration file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse YAML
	var config SSHPiperConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	
	// Set timestamps
	now := time.Now()
	if config.Metadata.CreatedAt.IsZero() {
		config.Metadata.CreatedAt = now
	}
	config.Metadata.UpdatedAt = now
	
	// Apply environment-specific overrides
	if err := dcm.applyEnvironmentOverrides(&config); err != nil {
		return nil, fmt.Errorf("failed to apply environment overrides: %w", err)
	}
	
	// Process templates
	if err := dcm.processTemplates(&config); err != nil {
		return nil, fmt.Errorf("failed to process templates: %w", err)
	}
	
	// Validate configuration
	if err := dcm.validateConfiguration(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	
	dcm.logger.Info("configuration loaded successfully", log.Fields{
		"name":         config.Metadata.Name,
		"plugins":      len(config.Spec.Plugins),
		"routes":       len(config.Spec.Routes),
		"environments": len(config.Spec.Environments),
	})
	
	return &config, nil
}

// SaveConfiguration saves a configuration to file
func (dcm *DeclarativeConfigManager) SaveConfiguration(config *SSHPiperConfig, path string) error {
	dcm.logger.Info("saving configuration", log.Fields{
		"path": path,
		"name": config.Metadata.Name,
	})
	
	// Update timestamp
	config.Metadata.UpdatedAt = time.Now()
	
	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	dcm.logger.Info("configuration saved successfully", log.Fields{
		"path": path,
	})
	
	return nil
}

// applyEnvironmentOverrides applies environment-specific configuration overrides
func (dcm *DeclarativeConfigManager) applyEnvironmentOverrides(config *SSHPiperConfig) error {
	envName := os.Getenv("SSHPIPER_ENVIRONMENT")
	if envName == "" {
		envName = "default"
	}
	
	override, exists := config.Spec.Environments[envName]
	if !exists {
		dcm.logger.Debug("no environment override found", log.Fields{
			"environment": envName,
		})
		return nil
	}
	
	dcm.logger.Info("applying environment overrides", log.Fields{
		"environment": envName,
	})
	
	// Apply global overrides
	if override.Global != nil {
		if err := dcm.mergeGlobalConfig(&config.Spec.Global, override.Global); err != nil {
			return fmt.Errorf("failed to merge global config: %w", err)
		}
	}
	
	// Apply security overrides
	if override.Security != nil {
		if err := dcm.mergeSecurityConfig(&config.Spec.Security, override.Security); err != nil {
			return fmt.Errorf("failed to merge security config: %w", err)
		}
	}
	
	// Apply plugin overrides
	for _, pluginOverride := range override.Plugins {
		if err := dcm.applyPluginOverride(config, &pluginOverride); err != nil {
			return fmt.Errorf("failed to apply plugin override: %w", err)
		}
	}
	
	// Apply route overrides
	for _, routeOverride := range override.Routes {
		if err := dcm.applyRouteOverride(config, &routeOverride); err != nil {
			return fmt.Errorf("failed to apply route override: %w", err)
		}
	}
	
	return nil
}

// mergeGlobalConfig merges global configuration overrides
func (dcm *DeclarativeConfigManager) mergeGlobalConfig(base *GlobalConfig, override *GlobalConfig) error {
	// Use reflection to merge configurations
	return dcm.mergeStructs(base, override)
}

// mergeSecurityConfig merges security configuration overrides
func (dcm *DeclarativeConfigManager) mergeSecurityConfig(base *SecurityConfig, override *SecurityConfig) error {
	// Use reflection to merge configurations
	return dcm.mergeStructs(base, override)
}

// mergeStructs uses reflection to merge struct fields
func (dcm *DeclarativeConfigManager) mergeStructs(base, override interface{}) error {
	baseValue := reflect.ValueOf(base).Elem()
	overrideValue := reflect.ValueOf(override).Elem()
	
	for i := 0; i < overrideValue.NumField(); i++ {
		overrideField := overrideValue.Field(i)
		baseField := baseValue.Field(i)
		
		if !overrideField.IsZero() && baseField.CanSet() {
			baseField.Set(overrideField)
		}
	}
	
	return nil
}

// applyPluginOverride applies plugin-specific overrides
func (dcm *DeclarativeConfigManager) applyPluginOverride(config *SSHPiperConfig, override *PluginOverride) error {
	for i := range config.Spec.Plugins {
		plugin := &config.Spec.Plugins[i]
		if plugin.Name == override.Name {
			if override.Enabled != nil {
				plugin.Enabled = *override.Enabled
			}
			if override.Config != nil {
				if plugin.Config == nil {
					plugin.Config = make(map[string]interface{})
				}
				for key, value := range override.Config {
					plugin.Config[key] = value
				}
			}
			break
		}
	}
	
	return nil
}

// applyRouteOverride applies route-specific overrides
func (dcm *DeclarativeConfigManager) applyRouteOverride(config *SSHPiperConfig, override *RouteOverride) error {
	for i := range config.Spec.Routes {
		route := &config.Spec.Routes[i]
		if route.Name == override.Name {
			if override.Enabled != nil {
				route.Enabled = *override.Enabled
			}
			if override.Target != nil {
				route.Target = *override.Target
			}
			break
		}
	}
	
	return nil
}

// processTemplates processes configuration templates
func (dcm *DeclarativeConfigManager) processTemplates(config *SSHPiperConfig) error {
	for i := range config.Spec.Plugins {
		plugin := &config.Spec.Plugins[i]
		if plugin.Template != "" {
			if err := dcm.applyTemplate(plugin); err != nil {
				return fmt.Errorf("failed to apply template to plugin %s: %w", plugin.Name, err)
			}
		}
	}
	
	return nil
}

// applyTemplate applies a template to a plugin configuration
func (dcm *DeclarativeConfigManager) applyTemplate(plugin *PluginSpec) error {
	template, exists := dcm.templates[plugin.Template]
	if !exists {
		return fmt.Errorf("template %s not found", plugin.Template)
	}
	
	dcm.logger.Debug("applying template", log.Fields{
		"plugin":   plugin.Name,
		"template": plugin.Template,
	})
	
	// Apply template configuration
	if plugin.Config == nil {
		plugin.Config = make(map[string]interface{})
	}
	
	for key, value := range template.Template {
		if _, exists := plugin.Config[key]; !exists {
			plugin.Config[key] = value
		}
	}
	
	return nil
}

// validateConfiguration validates a configuration against schemas
func (dcm *DeclarativeConfigManager) validateConfiguration(config *SSHPiperConfig) error {
	dcm.logger.Debug("validating configuration", log.Fields{
		"name": config.Metadata.Name,
	})
	
	// Validate API version and kind
	if config.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if config.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	
	// Validate metadata
	if config.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	
	// Validate plugins
	for i, plugin := range config.Spec.Plugins {
		if err := dcm.validatePlugin(&plugin, i); err != nil {
			return fmt.Errorf("plugin validation failed: %w", err)
		}
	}
	
	// Validate routes
	for i, route := range config.Spec.Routes {
		if err := dcm.validateRoute(&route, i); err != nil {
			return fmt.Errorf("route validation failed: %w", err)
		}
	}
	
	// Validate global configuration
	if err := dcm.validateGlobalConfig(&config.Spec.Global); err != nil {
		return fmt.Errorf("global config validation failed: %w", err)
	}
	
	dcm.logger.Debug("configuration validation completed", log.Fields{
		"name": config.Metadata.Name,
	})
	
	return nil
}

// validatePlugin validates a plugin configuration
func (dcm *DeclarativeConfigManager) validatePlugin(plugin *PluginSpec, index int) error {
	if plugin.Name == "" {
		return fmt.Errorf("plugin[%d].name is required", index)
	}
	
	if plugin.Type == "" {
		return fmt.Errorf("plugin[%d].type is required", index)
	}
	
	// Validate plugin type
	validTypes := []PluginType{
		PluginTypeSimpleAuth,
		PluginTypeFileBased,
		PluginTypeAPIBased,
		PluginTypeContainerBased,
	}
	
	validType := false
	for _, vt := range validTypes {
		if plugin.Type == vt {
			validType = true
			break
		}
	}
	
	if !validType {
		return fmt.Errorf("plugin[%d].type %s is not valid", index, plugin.Type)
	}
	
	// Validate dependencies
	for _, dep := range plugin.Dependencies {
		if dep == plugin.Name {
			return fmt.Errorf("plugin[%d] cannot depend on itself", index)
		}
	}
	
	return nil
}

// validateRoute validates a route configuration
func (dcm *DeclarativeConfigManager) validateRoute(route *RouteSpec, index int) error {
	if route.Name == "" {
		return fmt.Errorf("route[%d].name is required", index)
	}
	
	if route.Target.Type == "" {
		return fmt.Errorf("route[%d].target.type is required", index)
	}
	
	// Validate target type
	validTargetTypes := []string{"plugin", "static", "dynamic"}
	validTargetType := false
	for _, vtt := range validTargetTypes {
		if route.Target.Type == vtt {
			validTargetType = true
			break
		}
	}
	
	if !validTargetType {
		return fmt.Errorf("route[%d].target.type %s is not valid", index, route.Target.Type)
	}
	
	// Validate plugin target
	if route.Target.Type == "plugin" && route.Target.Plugin == "" {
		return fmt.Errorf("route[%d].target.plugin is required when type is 'plugin'", index)
	}
	
	return nil
}

// validateGlobalConfig validates global configuration
func (dcm *DeclarativeConfigManager) validateGlobalConfig(global *GlobalConfig) error {
	// Validate server configuration
	if global.Server.ListenPort <= 0 || global.Server.ListenPort > 65535 {
		return fmt.Errorf("global.server.listenPort must be between 1 and 65535")
	}
	
	if global.Server.MaxConnections <= 0 {
		return fmt.Errorf("global.server.maxConnections must be positive")
	}
	
	// Validate connection configuration
	if global.Connection.MaxRetries < 0 {
		return fmt.Errorf("global.connection.maxRetries must be non-negative")
	}
	
	return nil
}

// LoadTemplates loads configuration templates
func (dcm *DeclarativeConfigManager) LoadTemplates(templateDir string) error {
	dcm.logger.Info("loading configuration templates", log.Fields{
		"template_dir": templateDir,
	})
	
	if _, err := os.Stat(templateDir); os.IsNotExist(err) {
		dcm.logger.Info("template directory does not exist, skipping template loading")
		return nil
	}
	
	templateCount := 0
	err := filepath.WalkDir(templateDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			return nil
		}
		
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			template, err := dcm.loadTemplate(path)
			if err != nil {
				dcm.logger.Error("failed to load template", err, log.Fields{
					"path": path,
				})
				return nil // Continue with other templates
			}
			
			dcm.templates[template.Name] = template
			templateCount++
			
			dcm.logger.Debug("loaded template", log.Fields{
				"name": template.Name,
				"path": path,
			})
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("failed to load templates: %w", err)
	}
	
	dcm.logger.Info("templates loaded successfully", log.Fields{
		"template_count": templateCount,
	})
	
	return nil
}

// loadTemplate loads a single template file
func (dcm *DeclarativeConfigManager) loadTemplate(path string) (*ConfigTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}
	
	var template ConfigTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template YAML: %w", err)
	}
	
	return &template, nil
}

// GenerateDefaultConfig generates a default configuration file
func (dcm *DeclarativeConfigManager) GenerateDefaultConfig() *SSHPiperConfig {
	now := time.Now()
	
	return &SSHPiperConfig{
		APIVersion: "sshpiper.com/v1",
		Kind:       "SSHPiperConfig",
		Metadata: ConfigMetadata{
			Name:      "default-sshpiper-config",
			Labels:    map[string]string{"environment": "default"},
			CreatedAt: now,
			UpdatedAt: now,
		},
		Spec: SSHPiperSpec{
			Global: GlobalConfig{
				Server: ServerConfig{
					ListenAddr:     "0.0.0.0",
					ListenPort:     2222,
					MaxConnections: 100,
					Timeout:        30 * time.Second,
					KeepAlive:      5 * time.Minute,
				},
				Connection: ConnectionConfig{
					MaxRetries:       3,
					RetryDelay:       1 * time.Second,
					ConnectTimeout:   10 * time.Second,
					HandshakeTimeout: 30 * time.Second,
					IdleTimeout:      10 * time.Minute,
					MaxChannels:      10,
					BufferSize:       32768,
				},
				Performance: PerformanceConfig{
					ConnectionPooling:   true,
					PoolSize:           10,
					PoolMaxIdle:        5 * time.Minute,
					CompressionEnabled: false,
					TCPNoDelay:         true,
					TCPKeepAlive:       true,
				},
				Features: FeatureFlags{
					HotReload:          true,
					PluginDiscovery:    true,
					AdvancedMetrics:    true,
					DistributedTracing: false,
					AuditLogging:       true,
					RateLimiting:       true,
					FailureBanning:     true,
				},
			},
			Security: SecurityConfig{
				Authentication: AuthenticationConfig{
					RequiredMethods: []string{"password", "publickey"},
					MaxAuthTries:    3,
					AuthTimeout:     30 * time.Second,
					PublicKeyAuth: PublicKeyAuthConfig{
						Enabled:           true,
						MinKeySize:        2048,
						AllowedAlgorithms: []string{"rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-256", "ecdsa-sha2-384", "ed25519"},
					},
					PasswordAuth: PasswordAuthConfig{
						Enabled:        true,
						MinLength:      8,
						RequireComplex: true,
					},
				},
				Authorization: AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					AuditEnabled:  true,
				},
				RateLimit: RateLimitConfig{
					Enabled:           true,
					ConnectionsPerIP:  10,
					ConnectionsPerUser: 5,
					WindowSize:        1 * time.Minute,
					BurstSize:         5,
				},
				FailureBan: FailureBanConfig{
					Enabled:     true,
					MaxFailures: 5,
					BanDuration: 10 * time.Minute,
					WindowSize:  5 * time.Minute,
				},
			},
			Observability: ObservabilityConfig{
				Logging: LoggingConfig{
					Level:      "info",
					Format:     "json",
					Output:     "stdout",
					MaxSize:    100,
					MaxAge:     7,
					MaxBackups: 3,
					Compress:   true,
				},
				Metrics: MetricsConfig{
					Enabled:   true,
					Port:      9090,
					Path:      "/metrics",
					Namespace: "sshpiper",
				},
				Tracing: TracingConfig{
					Enabled:     false,
					ServiceName: "sshpiper",
					SampleRate:  0.1,
					BatchSize:   100,
					Timeout:     5 * time.Second,
				},
				HealthCheck: HealthCheckConfig{
					Enabled:          true,
					Interval:         30 * time.Second,
					Timeout:          5 * time.Second,
					FailThreshold:    3,
					SuccessThreshold: 2,
				},
			},
			Plugins: []PluginSpec{
				{
					Name:      "fixed-target",
					Type:      PluginTypeSimpleAuth,
					Enabled:   false,
					HotReload: true,
					Resources: PluginResources{
						MaxMemoryMB:    128,
						MaxConnections: 50,
						Timeout:        30 * time.Second,
						RateLimit: RateLimit{
							RequestsPerSecond: 10,
							BurstSize:         5,
							WindowSize:        1 * time.Minute,
						},
					},
					Config: map[string]interface{}{
						"target": "192.168.1.100:22",
					},
				},
			},
			Routes: []RouteSpec{
				{
					Name:        "default-route",
					Description: "Default route for all connections",
					Enabled:     true,
					Priority:    100,
					Match: RouteMatch{
						Users: []string{"*"},
					},
					Target: RouteTarget{
						Type:   "plugin",
						Plugin: "fixed-target",
					},
					LoadBalancing: LoadBalancingConfig{
						Strategy:    "round_robin",
						HealthCheck: true,
					},
					RetryPolicy: RetryPolicyConfig{
						MaxRetries:    3,
						InitialDelay:  1 * time.Second,
						MaxDelay:      10 * time.Second,
						BackoffFactor: 2.0,
					},
				},
			},
		},
	}
}

// ConvertToJSON converts configuration to JSON format
func (dcm *DeclarativeConfigManager) ConvertToJSON(config *SSHPiperConfig) ([]byte, error) {
	return json.MarshalIndent(config, "", "  ")
}

// ConvertToYAML converts configuration to YAML format
func (dcm *DeclarativeConfigManager) ConvertToYAML(config *SSHPiperConfig) ([]byte, error) {
	return yaml.Marshal(config)
}

// ExportersConfig configures telemetry exporters
type ExportersConfig struct {
	Prometheus      PrometheusConfig     `yaml:"prometheus" json:"prometheus"`
}

// PrometheusConfig configures Prometheus metrics export
type PrometheusConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	Port            int    `yaml:"port" json:"port"`
	Path            string `yaml:"path" json:"path"`
	Namespace       string `yaml:"namespace" json:"namespace"`
	Subsystem       string `yaml:"subsystem" json:"subsystem"`
}