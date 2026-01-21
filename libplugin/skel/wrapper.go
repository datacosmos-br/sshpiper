package skel

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
)

// SpecProvider defines the interface for providing configuration specifications
type SpecProvider interface {
	GetFromSpecs() []interface{}
	GetToSpec() interface{}
}

// ValidatedSpecProvider adds validation to spec providers
type ValidatedSpecProvider interface {
	SpecProvider
	ValidateSpecs() error
}

// SecureSpec defines the interface for secure spec access
type SecureSpec interface {
	GetString(fieldName string) (string, error)
	GetBool(fieldName string) (bool, error)
	GetStringList(fieldName string) ([]string, error)
}

// StandardPipeWrapper provides robust implementations for common SkelPipe operations.
// Plugins can embed this struct and override only the methods they need to customize.
type StandardPipeWrapper struct {
	// BaseDir is the directory for resolving relative paths (required)
	BaseDir string

	// SpecProvider provides access to specifications
	SpecProvider SpecProvider

	// validated indicates if the wrapper has been validated
	validated bool
}

// NewStandardPipeWrapper creates a new StandardPipeWrapper with validation
func NewStandardPipeWrapper(baseDir string, provider SpecProvider) (*StandardPipeWrapper, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("baseDir cannot be empty")
	}

	if provider == nil {
		return nil, fmt.Errorf("SpecProvider cannot be nil")
	}

	// Validate base directory
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid baseDir %q: %w", baseDir, err)
	}

	wrapper := &StandardPipeWrapper{
		BaseDir:      absBaseDir,
		SpecProvider: provider,
	}

	// Validate the wrapper
	if err := wrapper.Validate(); err != nil {
		return nil, fmt.Errorf("wrapper validation failed: %w", err)
	}

	return wrapper, nil
}

// Validate performs comprehensive validation of the wrapper configuration
func (w *StandardPipeWrapper) Validate() error {
	if w.SpecProvider == nil {
		return fmt.Errorf("SpecProvider is required")
	}

	if w.BaseDir == "" {
		return fmt.Errorf("BaseDir is required")
	}

	// Validate base directory exists and is accessible
	if !filepath.IsAbs(w.BaseDir) {
		return fmt.Errorf("BaseDir must be absolute path: %q", w.BaseDir)
	}

	// Test provider access
	specs := w.SpecProvider.GetFromSpecs()
	if specs == nil {
		return fmt.Errorf("GetFromSpecs() returned nil")
	}

	toSpec := w.SpecProvider.GetToSpec()
	if toSpec == nil {
		return fmt.Errorf("GetToSpec() returned nil")
	}

	// If provider supports validation, use it
	if validatedProvider, ok := w.SpecProvider.(ValidatedSpecProvider); ok {
		if err := validatedProvider.ValidateSpecs(); err != nil {
			return fmt.Errorf("spec validation failed: %w", err)
		}
	}

	w.validated = true
	return nil
}

// ensureValidated checks if wrapper has been validated
func (w *StandardPipeWrapper) ensureValidated() error {
	if !w.validated {
		return fmt.Errorf("wrapper not validated - call Validate() first")
	}
	return nil
}

// TestPassword provides a secure implementation using libplugin.StandardTestPassword.
// It extracts htpasswd data/file from the first matching from spec.
func (w *StandardPipeWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	if err := w.ensureValidated(); err != nil {
		return false, err
	}

	if conn == nil {
		return false, fmt.Errorf("conn cannot be nil")
	}

	if len(password) == 0 {
		return false, fmt.Errorf("password cannot be empty")
	}

	username := conn.User()
	if username == "" {
		return false, fmt.Errorf("username cannot be empty")
	}

	// Extract htpasswd info from from specs safely
	var htpasswdData, htpasswdFile string
	specs := w.SpecProvider.GetFromSpecs()

	for i, spec := range specs {
		if spec == nil {
			continue
		}

		// Use safe field access
		if data := libplugin.GetFieldString(spec, "HtpasswdData"); data != "" {
			htpasswdData = data
			break
		}
		if file := libplugin.GetFieldString(spec, "HtpasswdFile"); file != "" {
			// Validate file path
			if err := validateFilePath(file); err != nil {
				return false, fmt.Errorf("invalid htpasswd file in spec %d: %w", i, err)
			}
			htpasswdFile = file
			break
		}
	}

	if htpasswdData == "" && htpasswdFile == "" {
		return false, fmt.Errorf("no htpasswd data or file found in specs")
	}

	return libplugin.StandardTestPassword(htpasswdData, htpasswdFile, username, password)
}

// AuthorizedKeys provides a secure implementation using libplugin.StandardAuthorizedKeys.
// It aggregates keys from all from specs with comprehensive validation.
func (w *StandardPipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	if err := w.ensureValidated(); err != nil {
		return nil, err
	}

	if conn == nil {
		return nil, fmt.Errorf("conn cannot be nil")
	}

	username := conn.User()
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": username}
	specs := w.SpecProvider.GetFromSpecs()

	for i, spec := range specs {
		if spec == nil {
			continue
		}

		// Extract authorized keys using safe field access
		keysData := libplugin.GetFieldString(spec, "AuthorizedKeysData")
		keysFile := libplugin.GetFieldString(spec, "AuthorizedKeys", "AuthorizedKeysFile")

		if keysFile != "" {
			if err := validateFilePath(keysFile); err != nil {
				return nil, fmt.Errorf("invalid authorized keys file in spec %d: %w", i, err)
			}
		}

		keys, err := libplugin.StandardAuthorizedKeys(keysData, keysFile, envVars, w.BaseDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load authorized keys from spec %d: %w", i, err)
		}

		if keys != nil && len(keys) > 0 {
			keysSources = append(keysSources, keys)
		}
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	// Join with proper line endings
	result := bytes.Join(keysSources, []byte("\n"))

	// Ensure result ends with newline if it has content
	if len(result) > 0 && !bytes.HasSuffix(result, []byte("\n")) {
		result = append(result, '\n')
	}

	return result, nil
}

// TrustedUserCAKeys provides a secure implementation using libplugin.StandardTrustedUserCAKeys.
// It aggregates CA keys from all from specs with validation.
func (w *StandardPipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	if err := w.ensureValidated(); err != nil {
		return nil, err
	}

	if conn == nil {
		return nil, fmt.Errorf("conn cannot be nil")
	}

	username := conn.User()
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": username}
	specs := w.SpecProvider.GetFromSpecs()

	for i, spec := range specs {
		if spec == nil {
			continue
		}

		// Extract CA keys using safe field access
		caKeysData := libplugin.GetFieldString(spec, "TrustedUserCAKeysData")
		caKeysFile := libplugin.GetFieldString(spec, "TrustedUserCAKeys", "TrustedUserCAKeysFile")

		if caKeysFile != "" {
			if err := validateFilePath(caKeysFile); err != nil {
				return nil, fmt.Errorf("invalid CA keys file in spec %d: %w", i, err)
			}
		}

		caKeys, err := libplugin.StandardTrustedUserCAKeys(caKeysData, caKeysFile, envVars, w.BaseDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA keys from spec %d: %w", i, err)
		}

		if caKeys != nil && len(caKeys) > 0 {
			keysSources = append(keysSources, caKeys)
		}
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	// Join with proper line endings
	result := bytes.Join(keysSources, []byte("\n"))

	// Ensure result ends with newline if it has content
	if len(result) > 0 && !bytes.HasSuffix(result, []byte("\n")) {
		result = append(result, '\n')
	}

	return result, nil
}

// StandardPipeToWrapper provides secure implementations for SkelPipeTo operations.
type StandardPipeToWrapper struct {
	// BaseDir is the directory for resolving relative paths (required)
	BaseDir string

	// Username is the target username (optional)
	Username string

	// SpecProvider provides access to to specification
	SpecProvider SpecProvider

	// validated indicates if the wrapper has been validated
	validated bool
}

// NewStandardPipeToWrapper creates a new StandardPipeToWrapper with validation
func NewStandardPipeToWrapper(baseDir, username string, provider SpecProvider) (*StandardPipeToWrapper, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("baseDir cannot be empty")
	}

	if provider == nil {
		return nil, fmt.Errorf("SpecProvider cannot be nil")
	}

	// Validate base directory
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid baseDir %q: %w", baseDir, err)
	}

	// Validate username if provided
	if username != "" {
		if err := validateUsername(username); err != nil {
			return nil, fmt.Errorf("invalid username %q: %w", username, err)
		}
	}

	wrapper := &StandardPipeToWrapper{
		BaseDir:      absBaseDir,
		Username:     username,
		SpecProvider: provider,
	}

	// Validate the wrapper
	if err := wrapper.Validate(); err != nil {
		return nil, fmt.Errorf("wrapper validation failed: %w", err)
	}

	return wrapper, nil
}

// Validate performs comprehensive validation of the wrapper configuration
func (w *StandardPipeToWrapper) Validate() error {
	if w.SpecProvider == nil {
		return fmt.Errorf("SpecProvider is required")
	}

	if w.BaseDir == "" {
		return fmt.Errorf("BaseDir is required")
	}

	// Validate base directory
	if !filepath.IsAbs(w.BaseDir) {
		return fmt.Errorf("BaseDir must be absolute path: %q", w.BaseDir)
	}

	// Test provider access
	toSpec := w.SpecProvider.GetToSpec()
	if toSpec == nil {
		return fmt.Errorf("GetToSpec() returned nil")
	}

	// Validate username if provided
	if w.Username != "" {
		if err := validateUsername(w.Username); err != nil {
			return fmt.Errorf("invalid username: %w", err)
		}
	}

	w.validated = true
	return nil
}

// ensureValidated checks if wrapper has been validated
func (w *StandardPipeToWrapper) ensureValidated() error {
	if !w.validated {
		return fmt.Errorf("wrapper not validated - call Validate() first")
	}
	return nil
}

// Host extracts the host from the to spec with validation.
func (w *StandardPipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	if err := w.ensureValidated(); err != nil {
		return ""
	}

	if conn == nil {
		return ""
	}

	spec := w.SpecProvider.GetToSpec()
	if spec == nil {
		return ""
	}

	host := libplugin.GetFieldString(spec, "Host")

	// Basic host validation
	if host != "" && !isValidHost(host) {
		return ""
	}

	return host
}

// User returns the configured username or falls back to the connection username.
func (w *StandardPipeToWrapper) User(conn libplugin.ConnMetadata) string {
	if err := w.ensureValidated(); err != nil {
		return ""
	}

	if conn == nil {
		return ""
	}

	if w.Username != "" {
		return w.Username
	}

	username := conn.User()
	if username != "" && isValidUsername(username) {
		return username
	}

	return ""
}

// IgnoreHostKey extracts the ignore_hostkey flag from the to spec.
func (w *StandardPipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	if err := w.ensureValidated(); err != nil {
		return false
	}

	if conn == nil {
		return false
	}

	spec := w.SpecProvider.GetToSpec()
	if spec == nil {
		return false
	}

	return libplugin.GetFieldBool(spec, "IgnoreHostkey", "IgnoreHostKey")
}

// KnownHosts loads known hosts data using secure helpers.
func (w *StandardPipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	if err := w.ensureValidated(); err != nil {
		return nil, err
	}

	if conn == nil {
		return nil, fmt.Errorf("conn cannot be nil")
	}

	spec := w.SpecProvider.GetToSpec()
	if spec == nil {
		return nil, fmt.Errorf("toSpec is nil")
	}

	username := conn.User()
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	envVars := map[string]string{
		"DOWNSTREAM_USER": username,
		"UPSTREAM_USER":   w.User(conn),
	}

	// Try multiple field names for compatibility
	knownHostsData := libplugin.GetFieldString(spec, "KnownHostsData")
	knownHostsFile := libplugin.GetFieldString(spec, "KnownHosts", "KnownHostsFile")

	if knownHostsFile != "" {
		if err := validateFilePath(knownHostsFile); err != nil {
			return nil, fmt.Errorf("invalid known hosts file: %w", err)
		}
	}

	return libplugin.LoadFileOrBase64(knownHostsFile, knownHostsData, envVars, w.BaseDir)
}

// StandardPipeToPasswordWrapper adds secure password override support.
type StandardPipeToPasswordWrapper struct {
	StandardPipeToWrapper
}

// NewStandardPipeToPasswordWrapper creates a new password wrapper with validation
func NewStandardPipeToPasswordWrapper(baseDir, username string, provider SpecProvider) (*StandardPipeToPasswordWrapper, error) {
	baseWrapper, err := NewStandardPipeToWrapper(baseDir, username, provider)
	if err != nil {
		return nil, err
	}

	return &StandardPipeToPasswordWrapper{
		StandardPipeToWrapper: *baseWrapper,
	}, nil
}

// OverridePassword loads an override password using secure helpers.
func (w *StandardPipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	if err := w.ensureValidated(); err != nil {
		return nil, err
	}

	if conn == nil {
		return nil, fmt.Errorf("conn cannot be nil")
	}

	spec := w.SpecProvider.GetToSpec()
	if spec == nil {
		return nil, fmt.Errorf("toSpec is nil")
	}

	username := conn.User()
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	envVars := map[string]string{
		"DOWNSTREAM_USER": username,
		"UPSTREAM_USER":   w.User(conn),
	}

	passwordData := libplugin.GetFieldString(spec, "Password", "PasswordData")
	passwordFile := libplugin.GetFieldString(spec, "PasswordFile")

	if passwordFile != "" {
		if err := validateFilePath(passwordFile); err != nil {
			return nil, fmt.Errorf("invalid password file: %w", err)
		}
	}

	return libplugin.StandardOverridePassword(passwordData, passwordFile, envVars, w.BaseDir)
}

// StandardPipeToPrivateKeyWrapper adds secure private key support.
type StandardPipeToPrivateKeyWrapper struct {
	StandardPipeToWrapper
}

// NewStandardPipeToPrivateKeyWrapper creates a new private key wrapper with validation
func NewStandardPipeToPrivateKeyWrapper(baseDir, username string, provider SpecProvider) (*StandardPipeToPrivateKeyWrapper, error) {
	baseWrapper, err := NewStandardPipeToWrapper(baseDir, username, provider)
	if err != nil {
		return nil, err
	}

	return &StandardPipeToPrivateKeyWrapper{
		StandardPipeToWrapper: *baseWrapper,
	}, nil
}

// PrivateKey loads private key and certificate using secure helpers.
func (w *StandardPipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	if err := w.ensureValidated(); err != nil {
		return nil, nil, err
	}

	if conn == nil {
		return nil, nil, fmt.Errorf("conn cannot be nil")
	}

	spec := w.SpecProvider.GetToSpec()
	if spec == nil {
		return nil, nil, fmt.Errorf("toSpec is nil")
	}

	username := conn.User()
	if username == "" {
		return nil, nil, fmt.Errorf("username cannot be empty")
	}

	envVars := map[string]string{
		"DOWNSTREAM_USER": username,
		"UPSTREAM_USER":   w.User(conn),
	}

	privateKeyData := libplugin.GetFieldString(spec, "PrivateKeyData")
	privateKeyFile := libplugin.GetFieldString(spec, "PrivateKey", "PrivateKeyFile")

	if privateKeyFile != "" {
		if err := validateFilePath(privateKeyFile); err != nil {
			return nil, nil, fmt.Errorf("invalid private key file: %w", err)
		}
	}

	return libplugin.StandardPrivateKey(privateKeyData, privateKeyFile, envVars, w.BaseDir)
}

// Validation helper functions

// validateFilePath validates a file path for security
func validateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Prevent directory traversal attacks
	if strings.Contains(path, "..") {
		return fmt.Errorf("file path cannot contain '..' (directory traversal)")
	}

	// Prevent absolute paths outside base directory
	if filepath.IsAbs(path) {
		return fmt.Errorf("absolute file paths not allowed for security")
	}

	return nil
}

// validateUsername validates a username for security
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if len(username) > 64 {
		return fmt.Errorf("username too long (max 64 characters)")
	}

	// Basic character validation
	if strings.ContainsAny(username, "\n\r\t\\/") {
		return fmt.Errorf("username contains invalid characters")
	}

	return nil
}

// isValidUsername checks if a username is valid
func isValidUsername(username string) bool {
	return validateUsername(username) == nil
}

// isValidHost checks if a host is valid (basic validation)
func isValidHost(host string) bool {
	if host == "" {
		return false
	}

	if len(host) > 255 {
		return false
	}

	// Basic validation - no control characters
	if strings.ContainsAny(host, "\n\r\t") {
		return false
	}

	return true
}
