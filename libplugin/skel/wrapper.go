package skel

import (
	"bytes"

	"github.com/tg123/sshpiper/libplugin"
)

// StandardPipeWrapper provides default implementations for common SkelPipe operations.
// Plugins can embed this struct and override only the methods they need to customize.
type StandardPipeWrapper struct {
	// BaseDir is the directory for resolving relative paths
	BaseDir string
	
	// GetFromSpecs returns the from specifications for this pipe
	GetFromSpecs func() []interface{}
	
	// GetToSpec returns the to specification for this pipe
	GetToSpec func() interface{}
}

// TestPassword provides a standard implementation using libplugin.StandardTestPassword.
// It extracts htpasswd data/file from the first matching from spec.
func (w *StandardPipeWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	// Extract htpasswd info from from specs
	var htpasswdData, htpasswdFile string
	
	for _, spec := range w.GetFromSpecs() {
		// Use reflection to safely extract fields
		if data := libplugin.GetFieldString(spec, "HtpasswdData"); data != "" {
			htpasswdData = data
			break
		}
		if file := libplugin.GetFieldString(spec, "HtpasswdFile"); file != "" {
			htpasswdFile = file
			break
		}
	}
	
	return libplugin.StandardTestPassword(htpasswdData, htpasswdFile, conn.User(), password)
}

// AuthorizedKeys provides a standard implementation using libplugin.StandardAuthorizedKeys.
// It aggregates keys from all from specs.
func (w *StandardPipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	
	for _, spec := range w.GetFromSpecs() {
		// Extract authorized keys using standard patterns
		keysData := libplugin.GetFieldString(spec, "AuthorizedKeysData")
		keysFile := libplugin.GetFieldString(spec, "AuthorizedKeys", "AuthorizedKeysFile")
		
		keys, err := libplugin.StandardAuthorizedKeys(keysData, keysFile, envVars, w.BaseDir)
		if err != nil {
			return nil, err
		}
		if keys != nil {
			keysSources = append(keysSources, keys)
		}
	}
	
	if len(keysSources) == 0 {
		return nil, nil
	}
	
	return bytes.Join(keysSources, []byte("\n")), nil
}

// TrustedUserCAKeys provides a standard implementation using libplugin.StandardTrustedUserCAKeys.
// It aggregates CA keys from all from specs.
func (w *StandardPipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	
	for _, spec := range w.GetFromSpecs() {
		// Extract CA keys using standard patterns
		caKeysData := libplugin.GetFieldString(spec, "TrustedUserCAKeysData")
		caKeysFile := libplugin.GetFieldString(spec, "TrustedUserCAKeys", "TrustedUserCAKeysFile")
		
		caKeys, err := libplugin.StandardTrustedUserCAKeys(caKeysData, caKeysFile, envVars, w.BaseDir)
		if err != nil {
			return nil, err
		}
		if caKeys != nil {
			keysSources = append(keysSources, caKeys)
		}
	}
	
	if len(keysSources) == 0 {
		return nil, nil
	}
	
	return bytes.Join(keysSources, []byte("\n")), nil
}

// StandardPipeToWrapper provides default implementations for SkelPipeTo operations.
type StandardPipeToWrapper struct {
	// BaseDir is the directory for resolving relative paths
	BaseDir string
	
	// Username is the target username
	Username string
	
	// GetToSpec returns the to specification
	GetToSpec func() interface{}
}

// Host extracts the host from the to spec.
func (w *StandardPipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	spec := w.GetToSpec()
	return libplugin.GetFieldString(spec, "Host")
}

// User returns the configured username or falls back to the connection username.
func (w *StandardPipeToWrapper) User(conn libplugin.ConnMetadata) string {
	if w.Username != "" {
		return w.Username
	}
	return conn.User()
}

// IgnoreHostKey extracts the ignore_hostkey flag from the to spec.
func (w *StandardPipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	spec := w.GetToSpec()
	return libplugin.GetFieldBool(spec, "IgnoreHostkey", "IgnoreHostKey")
}

// KnownHosts loads known hosts data using standard helpers.
func (w *StandardPipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	spec := w.GetToSpec()
	envVars := map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   w.User(conn),
	}
	
	// Try multiple field names for compatibility
	knownHostsData := libplugin.GetFieldString(spec, "KnownHostsData")
	knownHostsFile := libplugin.GetFieldString(spec, "KnownHosts", "KnownHostsFile")
	
	return libplugin.LoadFileOrBase64(knownHostsFile, knownHostsData, envVars, w.BaseDir)
}

// StandardPipeToPasswordWrapper adds password override support.
type StandardPipeToPasswordWrapper struct {
	StandardPipeToWrapper
}

// OverridePassword loads an override password using standard helpers.
func (w *StandardPipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	spec := w.GetToSpec()
	envVars := map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   w.User(conn),
	}
	
	passwordData := libplugin.GetFieldString(spec, "Password", "PasswordData")
	passwordFile := libplugin.GetFieldString(spec, "PasswordFile")
	
	return libplugin.StandardOverridePassword(passwordData, passwordFile, envVars, w.BaseDir)
}

// StandardPipeToPrivateKeyWrapper adds private key support.
type StandardPipeToPrivateKeyWrapper struct {
	StandardPipeToWrapper
}

// PrivateKey loads private key and certificate using standard helpers.
func (w *StandardPipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	spec := w.GetToSpec()
	envVars := map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   w.User(conn),
	}
	
	privateKeyData := libplugin.GetFieldString(spec, "PrivateKeyData")
	privateKeyFile := libplugin.GetFieldString(spec, "PrivateKey", "PrivateKeyFile")
	
	return libplugin.StandardPrivateKey(privateKeyData, privateKeyFile, envVars, w.BaseDir)
}