package libplugin

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ValidationLevel represents the strictness of validation
type ValidationLevel int

const (
	ValidationLevelPermissive ValidationLevel = iota // Allow most inputs with warnings
	ValidationLevelStandard                          // Standard validation with reasonable restrictions
	ValidationLevelStrict                            // Strict validation for high-security environments
)

// ValidationRule represents a single validation rule
type ValidationRule struct {
	Name        string
	Description string
	Level       ValidationLevel
	Validator   func(interface{}) error
}

// ValidationResult represents the result of validation
type ValidationResult struct {
	Valid    bool
	Errors   []error
	Warnings []string
	Level    ValidationLevel
}

// StandardValidationFramework provides comprehensive validation functionality
type StandardValidationFramework struct {
	level     ValidationLevel
	logger    *StandardLogger
	rules     map[string][]ValidationRule
	customRules map[string]ValidationRule
}

// NewStandardValidationFramework creates a new validation framework
func NewStandardValidationFramework(pluginName string, level ValidationLevel) *StandardValidationFramework {
	svf := &StandardValidationFramework{
		level:       level,
		logger:      NewStandardLogger(fmt.Sprintf("%s_validation", pluginName)),
		rules:       make(map[string][]ValidationRule),
		customRules: make(map[string]ValidationRule),
	}
	
	// Initialize built-in validation rules
	svf.initializeBuiltinRules()
	
	return svf
}

// initializeBuiltinRules sets up the standard validation rules
func (svf *StandardValidationFramework) initializeBuiltinRules() {
	// Connection validation rules
	svf.AddRule("connection", ValidationRule{
		Name:        "validate_connection_metadata",
		Description: "Validates SSH connection metadata",
		Level:       ValidationLevelStandard,
		Validator:   svf.validateConnectionMetadata,
	})
	
	// Host validation rules
	svf.AddRule("host", ValidationRule{
		Name:        "validate_host_format",
		Description: "Validates host format (hostname or IP)",
		Level:       ValidationLevelStandard,
		Validator:   svf.validateHost,
	})
	
	svf.AddRule("host", ValidationRule{
		Name:        "validate_host_not_localhost",
		Description: "Prevents localhost connections in production",
		Level:       ValidationLevelStrict,
		Validator:   svf.validateNotLocalhost,
	})
	
	// Port validation rules
	svf.AddRule("port", ValidationRule{
		Name:        "validate_port_range",
		Description: "Validates port is in valid range (1-65535)",
		Level:       ValidationLevelStandard,
		Validator:   svf.validatePortRange,
	})
	
	svf.AddRule("port", ValidationRule{
		Name:        "validate_port_not_privileged",
		Description: "Warns about privileged ports (<1024)",
		Level:       ValidationLevelStrict,
		Validator:   svf.validateNotPrivilegedPort,
	})
	
	// Username validation rules
	svf.AddRule("username", ValidationRule{
		Name:        "validate_username_format",
		Description: "Validates username format",
		Level:       ValidationLevelStandard,
		Validator:   svf.validateUsernameFormat,
	})
	
	svf.AddRule("username", ValidationRule{
		Name:        "validate_username_not_system",
		Description: "Warns about system usernames",
		Level:       ValidationLevelStrict,
		Validator:   svf.validateNotSystemUsername,
	})
	
	// Password validation rules
	svf.AddRule("password", ValidationRule{
		Name:        "validate_password_not_empty",
		Description: "Validates password is not empty",
		Level:       ValidationLevelStandard,
		Validator:   svf.validatePasswordNotEmpty,
	})
	
	svf.AddRule("password", ValidationRule{
		Name:        "validate_password_strength",
		Description: "Validates password strength",
		Level:       ValidationLevelStrict,
		Validator:   svf.validatePasswordStrength,
	})
	
	// File path validation rules
	svf.AddRule("file_path", ValidationRule{
		Name:        "validate_file_exists",
		Description: "Validates file exists and is readable",
		Level:       ValidationLevelStandard,
		Validator:   svf.validateFileExists,
	})
	
	svf.AddRule("file_path", ValidationRule{
		Name:        "validate_file_not_world_writable",
		Description: "Validates file is not world writable",
		Level:       ValidationLevelStrict,
		Validator:   svf.validateFileNotWorldWritable,
	})
	
	// SSH key validation rules
	svf.AddRule("ssh_key", ValidationRule{
		Name:        "validate_ssh_key_format",
		Description: "Validates SSH key format",
		Level:       ValidationLevelStandard,
		Validator:   svf.validateSSHKeyFormat,
	})
	
	svf.AddRule("ssh_key", ValidationRule{
		Name:        "validate_ssh_key_strength",
		Description: "Validates SSH key strength",
		Level:       ValidationLevelStrict,
		Validator:   svf.validateSSHKeyStrength,
	})
}

// AddRule adds a custom validation rule
func (svf *StandardValidationFramework) AddRule(category string, rule ValidationRule) {
	if svf.rules[category] == nil {
		svf.rules[category] = make([]ValidationRule, 0)
	}
	svf.rules[category] = append(svf.rules[category], rule)
}

// AddCustomRule adds a named custom validation rule
func (svf *StandardValidationFramework) AddCustomRule(name string, rule ValidationRule) {
	svf.customRules[name] = rule
}

// ValidateValue validates a single value against rules for a category
func (svf *StandardValidationFramework) ValidateValue(category string, value interface{}) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   make([]error, 0),
		Warnings: make([]string, 0),
		Level:    svf.level,
	}
	
	rules, exists := svf.rules[category]
	if !exists {
		svf.logger.Debug("no validation rules found for category", log.Fields{
			"category": category,
		})
		return result
	}
	
	svf.logger.Debug("validating value", log.Fields{
		"category":   category,
		"rule_count": len(rules),
		"level":      svf.level,
	})
	
	for _, rule := range rules {
		// Skip rules that are above our validation level
		if rule.Level > svf.level {
			continue
		}
		
		err := rule.Validator(value)
		if err != nil {
			if rule.Level == ValidationLevelStrict && svf.level < ValidationLevelStrict {
				// Convert strict errors to warnings for lower levels
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %s", rule.Name, err.Error()))
			} else {
				result.Errors = append(result.Errors, fmt.Errorf("%s: %w", rule.Name, err))
				result.Valid = false
			}
		}
	}
	
	if !result.Valid {
		svf.logger.Error("validation failed", fmt.Errorf("validation errors: %v", result.Errors), log.Fields{
			"category":     category,
			"error_count":  len(result.Errors),
			"warning_count": len(result.Warnings),
		})
	} else if len(result.Warnings) > 0 {
		svf.logger.Debug("validation passed with warnings", log.Fields{
			"category":      category,
			"warning_count": len(result.Warnings),
			"warnings":      result.Warnings,
		})
	} else {
		svf.logger.Debug("validation passed", log.Fields{
			"category": category,
		})
	}
	
	return result
}

// ValidateCustom validates a value against a named custom rule
func (svf *StandardValidationFramework) ValidateCustom(ruleName string, value interface{}) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   make([]error, 0),
		Warnings: make([]string, 0),
		Level:    svf.level,
	}
	
	rule, exists := svf.customRules[ruleName]
	if !exists {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Errorf("custom rule %s not found", ruleName))
		return result
	}
	
	err := rule.Validator(value)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Errorf("%s: %w", rule.Name, err))
	}
	
	return result
}

// ValidateStruct validates a struct using field tags or explicit rules
func (svf *StandardValidationFramework) ValidateStruct(obj interface{}) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   make([]error, 0),
		Warnings: make([]string, 0),
		Level:    svf.level,
	}
	
	// This would use reflection to validate struct fields
	// For now, it's a placeholder that could be extended
	svf.logger.Debug("struct validation not yet implemented", log.Fields{
		"type": fmt.Sprintf("%T", obj),
	})
	
	return result
}

// Built-in validation functions

func (svf *StandardValidationFramework) validateConnectionMetadata(value interface{}) error {
	conn, ok := value.(ConnMetadata)
	if !ok {
		return fmt.Errorf("expected ConnMetadata, got %T", value)
	}
	
	if conn == nil {
		return fmt.Errorf("connection metadata cannot be nil")
	}
	
	if conn.User() == "" {
		return fmt.Errorf("connection user cannot be empty")
	}
	
	if conn.RemoteAddr() == "" {
		return fmt.Errorf("remote address cannot be empty")
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateHost(value interface{}) error {
	host, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}
	
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	
	// Check if it's an IP address
	if ip := net.ParseIP(host); ip != nil {
		return nil // Valid IP address
	}
	
	// Check if it's a valid hostname
	if len(host) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}
	
	// Basic hostname validation
	hostRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !hostRegex.MatchString(host) {
		return fmt.Errorf("invalid hostname format")
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateNotLocalhost(value interface{}) error {
	host, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}
	
	// Check for localhost variants
	localhosts := []string{"localhost", "127.0.0.1", "::1", "0.0.0.0"}
	for _, localhost := range localhosts {
		if strings.EqualFold(host, localhost) {
			return fmt.Errorf("localhost connections not recommended in production")
		}
	}
	
	return nil
}

func (svf *StandardValidationFramework) validatePortRange(value interface{}) error {
	var port int
	
	switch v := value.(type) {
	case int:
		port = v
	case int32:
		port = int(v)
	case string:
		var err error
		port, err = strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid port format: %w", err)
		}
	default:
		return fmt.Errorf("expected int, int32, or string, got %T", value)
	}
	
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateNotPrivilegedPort(value interface{}) error {
	var port int
	
	switch v := value.(type) {
	case int:
		port = v
	case int32:
		port = int(v)
	case string:
		var err error
		port, err = strconv.Atoi(v)
		if err != nil {
			return nil // Skip if not parseable
		}
	default:
		return nil // Skip if not supported type
	}
	
	if port < 1024 {
		return fmt.Errorf("privileged port %d may require special permissions", port)
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateUsernameFormat(value interface{}) error {
	username, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}
	
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	
	if len(username) > 32 {
		return fmt.Errorf("username too long (max 32 characters)")
	}
	
	// Basic username validation (alphanumeric, underscore, hyphen)
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username contains invalid characters")
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateNotSystemUsername(value interface{}) error {
	username, ok := value.(string)
	if !ok {
		return nil // Skip if not string
	}
	
	// Common system usernames to warn about
	systemUsers := []string{"root", "bin", "daemon", "adm", "lp", "sync", "shutdown", "halt", "mail", "operator", "games", "ftp", "nobody", "systemd-network", "dbus"}
	
	for _, sysUser := range systemUsers {
		if strings.EqualFold(username, sysUser) {
			return fmt.Errorf("system username '%s' should be used carefully", username)
		}
	}
	
	return nil
}

func (svf *StandardValidationFramework) validatePasswordNotEmpty(value interface{}) error {
	switch v := value.(type) {
	case string:
		if v == "" {
			return fmt.Errorf("password cannot be empty")
		}
	case []byte:
		if len(v) == 0 {
			return fmt.Errorf("password cannot be empty")
		}
	default:
		return fmt.Errorf("expected string or []byte, got %T", value)
	}
	
	return nil
}

func (svf *StandardValidationFramework) validatePasswordStrength(value interface{}) error {
	var password string
	
	switch v := value.(type) {
	case string:
		password = v
	case []byte:
		password = string(v)
	default:
		return nil // Skip if not supported type
	}
	
	if len(password) < 8 {
		return fmt.Errorf("password should be at least 8 characters long")
	}
	
	// Check for basic complexity
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password)
	
	complexity := 0
	if hasUpper {
		complexity++
	}
	if hasLower {
		complexity++
	}
	if hasDigit {
		complexity++
	}
	if hasSpecial {
		complexity++
	}
	
	if complexity < 3 {
		return fmt.Errorf("password should contain at least 3 of: uppercase, lowercase, digits, special characters")
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateFileExists(value interface{}) error {
	filePath, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}
	
	if filePath == "" {
		return nil // Optional field
	}
	
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file not accessible: %w", err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file")
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateFileNotWorldWritable(value interface{}) error {
	filePath, ok := value.(string)
	if !ok {
		return nil // Skip if not string
	}
	
	if filePath == "" {
		return nil // Optional field
	}
	
	info, err := os.Stat(filePath)
	if err != nil {
		return nil // Skip if file doesn't exist
	}
	
	mode := info.Mode()
	if mode&0002 != 0 {
		return fmt.Errorf("file is world writable (security risk)")
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateSSHKeyFormat(value interface{}) error {
	var keyData []byte
	
	switch v := value.(type) {
	case string:
		keyData = []byte(v)
	case []byte:
		keyData = v
	default:
		return fmt.Errorf("expected string or []byte, got %T", value)
	}
	
	if len(keyData) == 0 {
		return nil // Optional field
	}
	
	// Basic SSH key format validation
	keyStr := strings.TrimSpace(string(keyData))
	lines := strings.Split(keyStr, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		
		// Check for SSH key format (starts with key type)
		keyTypes := []string{"ssh-rsa", "ssh-dss", "ecdsa-sha2-", "ssh-ed25519", "ssh-", "-----BEGIN"}
		hasValidPrefix := false
		for _, keyType := range keyTypes {
			if strings.HasPrefix(line, keyType) {
				hasValidPrefix = true
				break
			}
		}
		
		if !hasValidPrefix {
			return fmt.Errorf("invalid SSH key format on line: %s", line[:min(50, len(line))])
		}
	}
	
	return nil
}

func (svf *StandardValidationFramework) validateSSHKeyStrength(value interface{}) error {
	var keyData []byte
	
	switch v := value.(type) {
	case string:
		keyData = []byte(v)
	case []byte:
		keyData = v
	default:
		return nil // Skip if not supported type
	}
	
	if len(keyData) == 0 {
		return nil // Optional field
	}
	
	keyStr := strings.TrimSpace(string(keyData))
	lines := strings.Split(keyStr, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Warn about weak key types
		if strings.HasPrefix(line, "ssh-dss") {
			return fmt.Errorf("DSA keys are considered weak and deprecated")
		}
		
		// Check RSA key length (approximate)
		if strings.HasPrefix(line, "ssh-rsa") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				keyLen := len(parts[1])
				// Rough estimate: 1024-bit ~372 chars, 2048-bit ~372-550 chars, 4096-bit ~550+ chars
				if keyLen < 400 {
					return fmt.Errorf("RSA key appears to be less than 2048 bits (weak)")
				}
			}
		}
	}
	
	return nil
}

// Utility function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ValidationPresets provides pre-configured validation frameworks for common scenarios

// NewPermissiveValidation creates a permissive validation framework (warnings only)
func NewPermissiveValidation(pluginName string) *StandardValidationFramework {
	return NewStandardValidationFramework(pluginName, ValidationLevelPermissive)
}

// NewStandardValidation creates a standard validation framework (reasonable restrictions)
func NewStandardValidation(pluginName string) *StandardValidationFramework {
	return NewStandardValidationFramework(pluginName, ValidationLevelStandard)
}

// NewStrictValidation creates a strict validation framework (high security)
func NewStrictValidation(pluginName string) *StandardValidationFramework {
	return NewStandardValidationFramework(pluginName, ValidationLevelStrict)
}

// StandardConnectionValidator provides pre-configured validation for connection data
type StandardConnectionValidator struct {
	framework *StandardValidationFramework
}

// NewConnectionValidator creates a new connection validator
func NewConnectionValidator(pluginName string, level ValidationLevel) *StandardConnectionValidator {
	return &StandardConnectionValidator{
		framework: NewStandardValidationFramework(pluginName, level),
	}
}

// ValidateConnection validates complete connection information
func (scv *StandardConnectionValidator) ValidateConnection(conn ConnMetadata, host string, port int, username string) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   make([]error, 0),
		Warnings: make([]string, 0),
		Level:    scv.framework.level,
	}
	
	// Validate each component
	connResult := scv.framework.ValidateValue("connection", conn)
	hostResult := scv.framework.ValidateValue("host", host)
	portResult := scv.framework.ValidateValue("port", port)
	userResult := scv.framework.ValidateValue("username", username)
	
	// Merge results
	results := []ValidationResult{connResult, hostResult, portResult, userResult}
	for _, r := range results {
		if !r.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, r.Errors...)
		}
		result.Warnings = append(result.Warnings, r.Warnings...)
	}
	
	return result
}

// ValidateAuth validates authentication data
func (scv *StandardConnectionValidator) ValidateAuth(password []byte, keyData []byte) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   make([]error, 0),
		Warnings: make([]string, 0),
		Level:    scv.framework.level,
	}
	
	if len(password) > 0 {
		passResult := scv.framework.ValidateValue("password", password)
		if !passResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, passResult.Errors...)
		}
		result.Warnings = append(result.Warnings, passResult.Warnings...)
	}
	
	if len(keyData) > 0 {
		keyResult := scv.framework.ValidateValue("ssh_key", keyData)
		if !keyResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, keyResult.Errors...)
		}
		result.Warnings = append(result.Warnings, keyResult.Warnings...)
	}
	
	return result
}