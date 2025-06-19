package libplugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// StandardAuthorizedKeys provides a generic authorized keys loading implementation
// that works with data, files, and base64 encoding
func StandardAuthorizedKeys(keysData, keysFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	var keysSources [][]byte

	// Add data if provided
	if keysData != "" {
		data, err := base64.StdEncoding.DecodeString(keysData)
		if err != nil {
			// If base64 decode fails, treat as raw data
			data = []byte(keysData)
		}
		keysSources = append(keysSources, data)
	}

	// Add file content if provided
	if keysFile != "" {
		// Expand environment variables in file path
		expandedPath := keysFile
		for key, value := range envVars {
			expandedPath = strings.ReplaceAll(expandedPath, fmt.Sprintf("${%s}", key), value)
		}

		// Make path absolute if relative
		if !filepath.IsAbs(expandedPath) {
			expandedPath = filepath.Join(baseDir, expandedPath)
		}

		data, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read authorized keys file %s: %w", expandedPath, err)
		}
		keysSources = append(keysSources, data)
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	// Join all key sources with newlines
	return bytes.Join(keysSources, []byte("\n")), nil
}

// StandardTrustedUserCAKeys provides a generic trusted CA keys loading implementation
// that works with data, files, and base64 encoding
func StandardTrustedUserCAKeys(caKeysData, caKeysFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	var keysSources [][]byte

	// Add data if provided
	if caKeysData != "" {
		data, err := base64.StdEncoding.DecodeString(caKeysData)
		if err != nil {
			// If base64 decode fails, treat as raw data
			data = []byte(caKeysData)
		}
		keysSources = append(keysSources, data)
	}

	// Add file content if provided
	if caKeysFile != "" {
		// Expand environment variables in file path
		expandedPath := caKeysFile
		for key, value := range envVars {
			expandedPath = strings.ReplaceAll(expandedPath, fmt.Sprintf("${%s}", key), value)
		}

		// Make path absolute if relative
		if !filepath.IsAbs(expandedPath) {
			expandedPath = filepath.Join(baseDir, expandedPath)
		}

		data, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read trusted CA keys file %s: %w", expandedPath, err)
		}
		keysSources = append(keysSources, data)
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	// Join all key sources with newlines
	return bytes.Join(keysSources, []byte("\n")), nil
}

// StandardKnownHosts provides a generic known hosts loading implementation
// that works with data, files, and base64 encoding
func StandardKnownHosts(knownHostsData, knownHostsFile string, envVars map[string]string, baseDir string) ([]byte, error) {
	var hostsSources [][]byte

	// Add data if provided
	if knownHostsData != "" {
		data, err := base64.StdEncoding.DecodeString(knownHostsData)
		if err != nil {
			// If base64 decode fails, treat as raw data
			data = []byte(knownHostsData)
		}
		hostsSources = append(hostsSources, data)
	}

	// Add file content if provided
	if knownHostsFile != "" {
		// Expand environment variables in file path
		expandedPath := knownHostsFile
		for key, value := range envVars {
			expandedPath = strings.ReplaceAll(expandedPath, fmt.Sprintf("${%s}", key), value)
		}

		// Make path absolute if relative
		if !filepath.IsAbs(expandedPath) {
			expandedPath = filepath.Join(baseDir, expandedPath)
		}

		data, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read known hosts file %s: %w", expandedPath, err)
		}
		hostsSources = append(hostsSources, data)
	}

	if len(hostsSources) == 0 {
		return nil, nil
	}

	// Join all host sources with newlines
	return bytes.Join(hostsSources, []byte("\n")), nil
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
		data, err := base64.StdEncoding.DecodeString(passwordData)
		if err != nil {
			// If base64 decode fails, treat as raw data
			data = []byte(passwordData)
		}
		return data, nil
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
