package libplugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
)

// StandardTestPassword provides a generic password testing implementation
// that works with htpasswd data, files, and fallback authentication
func StandardTestPassword(htpasswdData, htpasswdFile string, username string, password []byte) (bool, error) {
	// Load htpasswd data from multiple sources
	var htpasswdSources [][]byte

	// Add data if provided
	if htpasswdData != "" {
		data, err := base64.StdEncoding.DecodeString(htpasswdData)
		if err != nil {
			// If base64 decode fails, treat as raw data
			data = []byte(htpasswdData)
		}
		htpasswdSources = append(htpasswdSources, data)
	}

	// Add file content if provided
	if htpasswdFile != "" {
		data, err := os.ReadFile(htpasswdFile)
		if err != nil {
			return false, fmt.Errorf("failed to read htpasswd file %s: %w", htpasswdFile, err)
		}
		htpasswdSources = append(htpasswdSources, data)
	}

	// If no password restrictions configured, allow connection
	if len(htpasswdSources) == 0 {
		return true, nil
	}

	// Test password against all htpasswd sources
	for _, data := range htpasswdSources {
		log.Debugf("testing password using htpasswd for user %s", username)
		auth, err := htpasswd.NewFromReader(bytes.NewReader(data), htpasswd.DefaultSystems, nil)
		if err != nil {
			log.Debugf("failed to parse htpasswd data: %v", err)
			continue
		}
		if auth.Match(username, string(password)) {
			return true, nil
		}
	}

	return false, nil
}

// standardLoadDataOrFile is a generic helper for loading data from base64 strings or files
func standardLoadDataOrFile(data, file string, envVars map[string]string, baseDir, description string) ([]byte, error) {
	var sources [][]byte

	// Add data if provided
	if data != "" {
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			// If base64 decode fails, treat as raw data
			decoded = []byte(data)
		}
		sources = append(sources, decoded)
	}

	// Add file content if provided
	if file != "" {
		// Expand environment variables in file path
		expandedPath := file
		for key, value := range envVars {
			expandedPath = strings.ReplaceAll(expandedPath, fmt.Sprintf("${%s}", key), value)
		}

		// Make path absolute if relative
		if !filepath.IsAbs(expandedPath) {
			expandedPath = filepath.Join(baseDir, expandedPath)
		}

		fileData, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s file %s: %w", description, expandedPath, err)
		}
		sources = append(sources, fileData)
	}

	if len(sources) == 0 {
		return nil, nil
	}

	// Join all sources with newlines
	return bytes.Join(sources, []byte("\n")), nil
}

// StandardAuthorizedKeys provides a generic authorized keys loading implementation
// that works with data, files, and base64 encoding
func StandardAuthorizedKeys(keysData, keysFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	return standardLoadDataOrFile(keysData, keysFile, envVars, baseDir, "authorized keys")
}

// StandardTrustedUserCAKeys provides a generic trusted CA keys loading implementation
// that works with data, files, and base64 encoding
func StandardTrustedUserCAKeys(caKeysData, caKeysFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	return standardLoadDataOrFile(caKeysData, caKeysFile, envVars, baseDir, "trusted CA keys")
}

// StandardKnownHosts provides a generic known hosts loading implementation
// that works with data, files, and base64 encoding
func StandardKnownHosts(knownHostsData, knownHostsFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	return standardLoadDataOrFile(knownHostsData, knownHostsFile, envVars, baseDir, "known hosts")
}

// StandardPrivateKey provides a generic private key loading implementation
// that works with data, files, and base64 encoding
func StandardPrivateKey(keyData, keyFile string, envVars map[string]string, baseDir string) ([]byte, []byte, error) {
	var keySources [][]byte

	// Add data if provided
	if keyData != "" {
		data, err := base64.StdEncoding.DecodeString(keyData)
		if err != nil {
			// If base64 decode fails, treat as raw data
			data = []byte(keyData)
		}
		keySources = append(keySources, data)
	}

	// Add file content if provided
	if keyFile != "" {
		// Expand environment variables in file path
		expandedPath := keyFile
		for key, value := range envVars {
			expandedPath = strings.ReplaceAll(expandedPath, fmt.Sprintf("${%s}", key), value)
		}

		// Make path absolute if relative
		if !filepath.IsAbs(expandedPath) {
			expandedPath = filepath.Join(baseDir, expandedPath)
		}

		data, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read private key file %s: %w", expandedPath, err)
		}
		keySources = append(keySources, data)
	}

	if len(keySources) == 0 {
		return nil, nil, nil
	}

	// Return first key source (private key only, no public key)
	return keySources[0], nil, nil
}

// StandardOverridePassword provides a generic override password loading implementation
func StandardOverridePassword(passwordData, passwordFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	// Add data if provided
	if passwordData != "" {
		// Only try base64 decoding if it really looks like base64
		if looksLikeBase64(passwordData) {
			data, err := base64.StdEncoding.DecodeString(passwordData)
			if err == nil {
				return data, nil
			}
		}
		// Otherwise treat as raw data
		return []byte(passwordData), nil
	}

	// Add file content if provided
	if passwordFile != "" {
		// Expand environment variables in file path
		expandedPath := passwordFile
		for key, value := range envVars {
			expandedPath = strings.ReplaceAll(expandedPath, fmt.Sprintf("${%s}", key), value)
		}

		// Make path absolute if relative
		if !filepath.IsAbs(expandedPath) {
			expandedPath = filepath.Join(baseDir, expandedPath)
		}

		data, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read password file %s: %w", expandedPath, err)
		}
		return data, nil
	}

	return nil, nil
}

// looksLikeBase64 checks if a string really looks like base64 (more conservative)
func looksLikeBase64(s string) bool {
	// Must be at least 8 characters and divisible by 4
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}

	// Must contain uppercase letters or numbers or + or / (typical base64 chars)
	hasUppercase := false
	hasNumbers := false
	hasSpecialChars := false

	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
		if c >= 'A' && c <= 'Z' {
			hasUppercase = true
		}
		if c >= '0' && c <= '9' {
			hasNumbers = true
		}
		if c == '+' || c == '/' {
			hasSpecialChars = true
		}
	}

	// Must have at least one characteristic of base64 (uppercase, numbers, or special chars)
	return hasUppercase || hasNumbers || hasSpecialChars
}

// StandardIgnoreHostKey provides a generic host key ignoring logic
func StandardIgnoreHostKey(ignoreHostKey bool, knownHostsData, knownHostsFile string) bool {
	// If explicitly set to ignore, return true
	if ignoreHostKey {
		return true
	}

	// If no known hosts configured, default to ignoring
	if knownHostsData == "" && knownHostsFile == "" {
		return true
	}

	// Have known hosts configuration, so validate
	return false
}

// StandardConfigLoader provides generic configuration loading functionality
type StandardConfigLoader struct {
	Name        string
	Description string
	Validators  []func(interface{}) error
}

// LoadAndValidate loads and validates configuration using the provided loader
func (scl *StandardConfigLoader) LoadAndValidate(data interface{}) error {
	for _, validator := range scl.Validators {
		if err := validator(data); err != nil {
			return fmt.Errorf("validation failed for %s: %w", scl.Name, err)
		}
	}
	return nil
}

// StandardValidator provides consistent validation patterns
type StandardValidator struct{}

// ValidateRequired checks if a string field is not empty
func (sv *StandardValidator) ValidateRequired(fieldName, value string) error {
	if value == "" {
		return fmt.Errorf("field %s is required", fieldName)
	}
	return nil
}

// ValidateHostPort validates host:port format
func (sv *StandardValidator) ValidateHostPort(fieldName, value string) error {
	if value == "" {
		return fmt.Errorf("field %s is required", fieldName)
	}
	_, _, err := SplitHostPortForSSH(value)
	if err != nil {
		return fmt.Errorf("field %s has invalid host:port format: %w", fieldName, err)
	}
	return nil
}

// ValidateFilePath validates file path exists and is readable
func (sv *StandardValidator) ValidateFilePath(fieldName, path string) error {
	if path == "" {
		return nil // Optional field
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("field %s file not accessible: %w", fieldName, err)
	}
	return nil
}

// StandardErrorHandler provides consistent error handling
type StandardErrorHandler struct {
	Logger *log.Logger
}

// HandleError logs and returns formatted error
func (seh *StandardErrorHandler) HandleError(operation, context string, err error) error {
	if seh.Logger != nil {
		seh.Logger.WithError(err).WithField("operation", operation).WithField("context", context).Error("operation failed")
	}
	return fmt.Errorf("%s failed in %s: %w", operation, context, err)
}

// WrapError wraps error with context
func (seh *StandardErrorHandler) WrapError(operation string, err error) error {
	if seh.Logger != nil {
		seh.Logger.WithError(err).WithField("operation", operation).Error("operation failed")
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// StandardLogger provides consistent logging functionality
type StandardLogger struct {
	Logger *log.Logger
	Fields log.Fields
}

// NewStandardLogger creates a new standard logger with consistent format
func NewStandardLogger(pluginName string) *StandardLogger {
	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})

	return &StandardLogger{
		Logger: logger,
		Fields: log.Fields{
			"plugin": pluginName,
		},
	}
}

// Info logs info message with standard fields
func (sl *StandardLogger) Info(message string, fields ...log.Fields) {
	entry := sl.Logger.WithFields(sl.Fields)
	for _, f := range fields {
		entry = entry.WithFields(f)
	}
	entry.Info(message)
}

// Error logs error message with standard fields
func (sl *StandardLogger) Error(message string, err error, fields ...log.Fields) {
	entry := sl.Logger.WithFields(sl.Fields).WithError(err)
	for _, f := range fields {
		entry = entry.WithFields(f)
	}
	entry.Error(message)
}

// Debug logs debug message with standard fields
func (sl *StandardLogger) Debug(message string, fields ...log.Fields) {
	entry := sl.Logger.WithFields(sl.Fields)
	for _, f := range fields {
		entry = entry.WithFields(f)
	}
	entry.Debug(message)
}

// StandardMetrics provides consistent metrics collection
type StandardMetrics struct {
	PluginName string
	Counters   map[string]int64
	Timers     map[string]time.Duration
	mutex      sync.RWMutex
}

// NewStandardMetrics creates a new metrics collector
func NewStandardMetrics(pluginName string) *StandardMetrics {
	return &StandardMetrics{
		PluginName: pluginName,
		Counters:   make(map[string]int64),
		Timers:     make(map[string]time.Duration),
	}
}

// IncrementCounter increments a named counter
func (sm *StandardMetrics) IncrementCounter(name string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.Counters[name]++
}

// RecordDuration records a duration for a named timer
func (sm *StandardMetrics) RecordDuration(name string, duration time.Duration) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.Timers[name] = duration
}

// GetCounters returns copy of all counters
func (sm *StandardMetrics) GetCounters() map[string]int64 {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	result := make(map[string]int64)
	for k, v := range sm.Counters {
		result[k] = v
	}
	return result
}

// GetTimers returns copy of all timers
func (sm *StandardMetrics) GetTimers() map[string]time.Duration {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	result := make(map[string]time.Duration)
	for k, v := range sm.Timers {
		result[k] = v
	}
	return result
}

// StandardPluginBase provides a base structure that all plugins should embed
type StandardPluginBase struct {
	Name         string
	Version      string
	Logger       *StandardLogger
	Metrics      *StandardMetrics
	Validator    *StandardValidator
	ErrorHandler *StandardErrorHandler
}

// NewStandardPluginBase creates a new plugin base with all standard components
func NewStandardPluginBase(name, version string) *StandardPluginBase {
	logger := NewStandardLogger(name)
	metrics := NewStandardMetrics(name)
	validator := &StandardValidator{}
	errorHandler := &StandardErrorHandler{Logger: logger.Logger}

	return &StandardPluginBase{
		Name:         name,
		Version:      version,
		Logger:       logger,
		Metrics:      metrics,
		Validator:    validator,
		ErrorHandler: errorHandler,
	}
}

// LogOperation logs the start and end of an operation with metrics
func (spb *StandardPluginBase) LogOperation(operation string, fn func() error) error {
	start := time.Now()
	spb.Logger.Debug(fmt.Sprintf("starting %s", operation))
	spb.Metrics.IncrementCounter(fmt.Sprintf("%s_attempts", operation))

	err := fn()
	duration := time.Since(start)
	spb.Metrics.RecordDuration(operation, duration)

	if err != nil {
		spb.Metrics.IncrementCounter(fmt.Sprintf("%s_errors", operation))
		spb.Logger.Error(fmt.Sprintf("%s failed", operation), err, log.Fields{
			"duration": duration,
		})
		return spb.ErrorHandler.WrapError(operation, err)
	}

	spb.Metrics.IncrementCounter(fmt.Sprintf("%s_success", operation))
	spb.Logger.Debug(fmt.Sprintf("%s completed successfully", operation), log.Fields{
		"duration": duration,
	})
	return nil
}

// ValidateConfig validates plugin configuration using standard patterns
func (spb *StandardPluginBase) ValidateConfig(config interface{}) error {
	return spb.LogOperation("config_validation", func() error {
		// This would be implemented by specific plugins
		return nil
	})
}

// StandardAuthData represents common authentication data structure
type StandardAuthData struct {
	// Password authentication
	PasswordFile   string `json:"password_file,omitempty"`
	PasswordData   string `json:"password_data,omitempty"`
	PasswordBase64 string `json:"password_base64,omitempty"`

	// Key authentication
	AuthorizedKeysFile   string `json:"authorized_keys_file,omitempty"`
	AuthorizedKeysData   string `json:"authorized_keys_data,omitempty"`
	AuthorizedKeysBase64 string `json:"authorized_keys_base64,omitempty"`

	// CA authentication
	TrustedUserCAKeysFile   string `json:"trusted_user_ca_keys_file,omitempty"`
	TrustedUserCAKeysData   string `json:"trusted_user_ca_keys_data,omitempty"`
	TrustedUserCAKeysBase64 string `json:"trusted_user_ca_keys_base64,omitempty"`
}

// StandardKeyData represents common key data structure
type StandardKeyData struct {
	// Known hosts
	KnownHostsFile   string `json:"known_hosts_file,omitempty"`
	KnownHostsData   string `json:"known_hosts_data,omitempty"`
	KnownHostsBase64 string `json:"known_hosts_base64,omitempty"`

	// Private keys
	PrivateKeyFile   string `json:"private_key_file,omitempty"`
	PrivateKeyData   string `json:"private_key_data,omitempty"`
	PrivateKeyBase64 string `json:"private_key_base64,omitempty"`

	// Override password
	OverridePasswordFile   string `json:"override_password_file,omitempty"`
	OverridePasswordData   string `json:"override_password_data,omitempty"`
	OverridePasswordBase64 string `json:"override_password_base64,omitempty"`
}

// StandardConnectionData represents common connection data structure
type StandardConnectionData struct {
	Host          string `json:"host,omitempty"`
	Port          int32  `json:"port,omitempty"`
	UserName      string `json:"user_name,omitempty"`
	IgnoreHostKey bool   `json:"ignore_host_key,omitempty"`
	Timeout       int    `json:"timeout,omitempty"`
	MaxRetries    int    `json:"max_retries,omitempty"`
}

// StandardPluginConfig represents the base configuration structure all plugins should use
type StandardPluginConfig struct {
	// Plugin metadata
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`

	// Common data structures
	AuthData       StandardAuthData       `json:"auth_data"`
	KeyData        StandardKeyData        `json:"key_data"`
	ConnectionData StandardConnectionData `json:"connection_data"`

	// Plugin-specific data (can be extended by individual plugins)
	PluginSpecific map[string]interface{} `json:"plugin_specific,omitempty"`
}

// Validate validates the standard plugin configuration
func (spc *StandardPluginConfig) Validate() error {
	validator := &StandardValidator{}

	// Validate required fields
	if err := validator.ValidateRequired("name", spc.Name); err != nil {
		return err
	}

	// Validate connection data if provided
	if spc.ConnectionData.Host != "" {
		hostPort := fmt.Sprintf("%s:%d", spc.ConnectionData.Host, spc.ConnectionData.Port)
		if err := validator.ValidateHostPort("connection_data.host:port", hostPort); err != nil {
			return err
		}
	}

	// Validate file paths if provided
	if err := validator.ValidateFilePath("auth_data.password_file", spc.AuthData.PasswordFile); err != nil {
		return err
	}
	if err := validator.ValidateFilePath("auth_data.authorized_keys_file", spc.AuthData.AuthorizedKeysFile); err != nil {
		return err
	}
	if err := validator.ValidateFilePath("auth_data.trusted_user_ca_keys_file", spc.AuthData.TrustedUserCAKeysFile); err != nil {
		return err
	}
	if err := validator.ValidateFilePath("key_data.known_hosts_file", spc.KeyData.KnownHostsFile); err != nil {
		return err
	}
	if err := validator.ValidateFilePath("key_data.private_key_file", spc.KeyData.PrivateKeyFile); err != nil {
		return err
	}
	if err := validator.ValidateFilePath("key_data.override_password_file", spc.KeyData.OverridePasswordFile); err != nil {
		return err
	}

	return nil
}

// GetAuthData returns the auth data with standard helper access
func (spc *StandardPluginConfig) GetAuthData() StandardAuthData {
	return spc.AuthData
}

// GetKeyData returns the key data with standard helper access
func (spc *StandardPluginConfig) GetKeyData() StandardKeyData {
	return spc.KeyData
}

// GetConnectionData returns the connection data with standard helper access
func (spc *StandardPluginConfig) GetConnectionData() StandardConnectionData {
	return spc.ConnectionData
}

// StandardPluginWrapper provides a standardized wrapper for all plugins
type StandardPluginWrapper struct {
	*StandardPluginBase
	Config *StandardPluginConfig
}

// NewStandardPluginWrapper creates a new standardized plugin wrapper
func NewStandardPluginWrapper(name, version, description string) *StandardPluginWrapper {
	base := NewStandardPluginBase(name, version)
	config := &StandardPluginConfig{
		Name:           name,
		Version:        version,
		Description:    description,
		PluginSpecific: make(map[string]interface{}),
	}

	return &StandardPluginWrapper{
		StandardPluginBase: base,
		Config:             config,
	}
}

// LoadConfig loads and validates configuration
func (spw *StandardPluginWrapper) LoadConfig(configData interface{}) error {
	return spw.LogOperation("load_config", func() error {
		// Convert configData to StandardPluginConfig
		// This would be implemented based on the source (JSON, YAML, etc.)
		return spw.Config.Validate()
	})
}

// GetStandardTestPasswordFunc returns a password testing function with metrics and logging
func (spw *StandardPluginWrapper) GetStandardTestPasswordFunc() func(ConnMetadata, []byte) (*Upstream, error) {
	return func(conn ConnMetadata, password []byte) (*Upstream, error) {
		var result *Upstream
		err := spw.LogOperation("test_password", func() error {
			// Implementation would call StandardTestPassword with proper parameters
			// This is a placeholder for the wrapper pattern
			return nil
		})
		return result, err
	}
}

// GetStandardAuthorizedKeysFunc returns an authorized keys function with metrics and logging
func (spw *StandardPluginWrapper) GetStandardAuthorizedKeysFunc() func(ConnMetadata, []byte) (*Upstream, error) {
	return func(conn ConnMetadata, key []byte) (*Upstream, error) {
		var result *Upstream
		err := spw.LogOperation("authorized_keys", func() error {
			// Implementation would call StandardAuthorizedKeys with proper parameters
			// This is a placeholder for the wrapper pattern
			return nil
		})
		return result, err
	}
}
