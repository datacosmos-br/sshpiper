// Package libplugin provides standard skeleton helpers for plugin implementations.
//
// This file contains standardized helpers for common plugin operations:
//   - standardLoadDataOrFile: Generic data loading from base64 or files
//   - StandardAuthorizedKeys: Load authorized keys from data or file
//   - StandardTrustedUserCAKeys: Load trusted CA keys from data or file
//   - StandardKnownHosts: Load known hosts from data or file
//   - StandardPrivateKey: Load private key from data or file
//   - StandardOverridePassword: Load override password from data or file
//   - StandardIgnoreHostKey: Determine if host key should be ignored
//
// These helpers reduce code duplication across plugins and provide consistent
// behavior for loading authentication data from various sources (base64, files).
package libplugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// standardLoadDataOrFile is a generic helper for loading data from base64 strings or files.
// It supports:
//   - Base64-encoded data (automatically detected and decoded)
//   - Raw data (if base64 decode fails)
//   - File paths with environment variable expansion
//   - Relative paths resolved against baseDir
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
// that works with data, files, and base64 encoding.
func StandardAuthorizedKeys(keysData, keysFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	return standardLoadDataOrFile(keysData, keysFile, envVars, baseDir, "authorized keys")
}

// StandardTrustedUserCAKeys provides a generic trusted CA keys loading implementation
// that works with data, files, and base64 encoding.
func StandardTrustedUserCAKeys(caKeysData, caKeysFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	return standardLoadDataOrFile(caKeysData, caKeysFile, envVars, baseDir, "trusted CA keys")
}

// StandardKnownHosts provides a generic known hosts loading implementation
// that works with data, files, and base64 encoding.
func StandardKnownHosts(knownHostsData, knownHostsFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	return standardLoadDataOrFile(knownHostsData, knownHostsFile, envVars, baseDir, "known hosts")
}

// StandardPrivateKey provides a generic private key loading implementation
// that works with data, files, and base64 encoding.
// Returns (privateKey, nil, error) - the second return value is reserved for future use.
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

// StandardOverridePassword provides a generic override password loading implementation.
// It supports base64-encoded passwords (auto-detected) or raw passwords.
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

// looksLikeBase64 checks if a string really looks like base64 (conservative detection).
// This prevents accidental base64 decoding of regular strings.
func looksLikeBase64(s string) bool {
	// Must be at least 8 characters and divisible by 4
	if len(s) < 8 || len(s)%4 != 0 {
		return false
	}

	// Must contain only valid base64 characters
	hasUppercase := false
	hasNumbers := false
	hasSpecialChars := false

	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '/' && c != '=' {
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

// StandardIgnoreHostKey provides generic host key ignoring logic.
// Returns true if host key verification should be skipped.
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
