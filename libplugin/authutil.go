// Package libplugin: Authentication Utility Helpers for SSHPiper Plugins
//
// This file provides Vault integration helpers for loading secrets:
//   - NewVaultClient: Create a Vault client from environment variables
//   - GetSecret: Retrieve and cache a Vault secret
//   - GetVaultSecretField: Get a specific field from a Vault secret
//   - GetVaultFieldAny: Get the first matching field from a Vault secret
//
// # Environment Variables
//   - VAULT_ADDR: Vault server address (required)
//   - VAULT_TOKEN: Vault authentication token (required)
//   - VAULT_CACHE_DURATION: Cache duration for secrets (default: 5m)
//
// # Usage Example
//
//	// Get a specific field from Vault
//	caKey, err := libplugin.GetVaultSecretField("secret/data/ssh-ca", "public_key")
//
//	// Get any of multiple possible field names
//	key, err := libplugin.GetVaultFieldAny("secret/data/ssh", []string{"private_key", "key"})
package libplugin

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// NewVaultClient creates a new Vault client using environment variables.
// Requires VAULT_ADDR and VAULT_TOKEN to be set.
func NewVaultClient() (*vault.Client, error) {
	cfg := vault.DefaultConfig()

	// VAULT_ADDR must be set in the environment (e.g., "https://vault.example.com")
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return nil, errors.New("VAULT_ADDR not set")
	}
	cfg.Address = addr

	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// VAULT_TOKEN must be set (or use another auth method like AppRole)
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, errors.New("VAULT_TOKEN not set")
	}
	client.SetToken(token)
	return client, nil
}

// getSecret retrieves a secret from the given path in Vault (uncached).
func getSecret(path string) (map[string]any, error) {
	client, err := NewVaultClient()
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("no data found at Vault path: " + path)
	}
	return secret.Data, nil
}

// Global cache for Vault secrets
var (
	vaultCache      = make(map[string]vaultCacheEntry)
	vaultCacheMutex sync.RWMutex
	// VAULT_CACHE_DURATION as a duration string (e.g. "5m"); default to 5 minutes if not set.
	vaultCacheDuration = func() time.Duration {
		if dStr := os.Getenv("VAULT_CACHE_DURATION"); dStr != "" {
			d, err := time.ParseDuration(dStr)
			if err == nil {
				return d
			}
		}
		return 5 * time.Minute
	}()
)

type vaultCacheEntry struct {
	secretData map[string]any
	expiry     time.Time
}

// GetSecret retrieves and caches a Vault secret at the given path.
// Uses a global cache with configurable expiry (VAULT_CACHE_DURATION environment variable).
func GetSecret(path string) (map[string]any, error) {
	vaultCacheMutex.RLock()
	entry, found := vaultCache[path]
	vaultCacheMutex.RUnlock()
	if found && time.Now().Before(entry.expiry) {
		return entry.secretData, nil
	}
	secretData, err := getSecret(path)
	if err != nil {
		return nil, err
	}
	vaultCacheMutex.Lock()
	vaultCache[path] = vaultCacheEntry{
		secretData: secretData,
		expiry:     time.Now().Add(vaultCacheDuration),
	}
	vaultCacheMutex.Unlock()
	return secretData, nil
}

// GetVaultSecretField retrieves a string field from a Vault secret at the given path.
// Returns the field value as []byte, or an error if not found or not a string.
func GetVaultSecretField(path, field string) ([]byte, error) {
	secretData, err := GetSecret(path)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Vault secret from %s: %v", path, err)
	}
	val, ok := secretData[field].(string)
	if !ok || val == "" {
		return nil, fmt.Errorf("field %q not found in Vault secret at %s", field, path)
	}
	return []byte(val), nil
}

// GetVaultFieldAny tries each field name in order and returns the first found value from Vault.
// Returns the field value as []byte, or an error if none of the fields are found.
func GetVaultFieldAny(path string, fieldNames []string) ([]byte, error) {
	for _, field := range fieldNames {
		val, err := GetVaultSecretField(path, field)
		if err == nil && len(val) > 0 {
			return val, nil
		}
	}
	return nil, fmt.Errorf("no matching field found in Vault secret at %s", path)
}

// LoadTrustedUserCAKeysMulti loads and aggregates trusted CA public keys from multiple sources.
// It combines keys from:
//   - files: ListOrString of file paths (supports variable expansion)
//   - base64Data: ListOrString of base64-encoded key data
//   - vaultPath: Vault secret path (uses "ca-key" or "public_key" field)
//
// All sources are combined with newlines. This enables flexible CA configuration
// where organizations can use any combination of files, inline data, and Vault secrets.
//
// Example usage:
//
//	caKeys, err := LoadTrustedUserCAKeysMulti(
//	    ListOrString{List: []string{"/etc/ssh/ca1.pub", "/etc/ssh/ca2.pub"}},
//	    ListOrString{Str: "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUJhd..."},
//	    "secret/data/ssh-ca",
//	    map[string]string{"TEAM": "engineering"},
//	    "/etc/sshpiper",
//	)
func LoadTrustedUserCAKeysMulti(files, base64Data ListOrString, vaultPath string, vars map[string]string, baseDir string) ([]byte, error) {
	var allKeys [][]byte

	// Load from files and base64 data using existing helper
	if files.Any() || base64Data.Any() {
		keys, err := LoadFileOrBase64Many(files, base64Data, vars, baseDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA keys from files/data: %w", err)
		}
		if len(keys) > 0 {
			allKeys = append(allKeys, keys)
		}
	}

	// Load from Vault if path provided
	if vaultPath != "" {
		// Try common field names for CA public keys
		vaultKeys, err := GetVaultFieldAny(vaultPath, []string{"ca-key", "public_key", "ca_key", "key"})
		if err != nil {
			return nil, fmt.Errorf("failed to load CA keys from Vault: %w", err)
		}
		if len(vaultKeys) > 0 {
			allKeys = append(allKeys, vaultKeys)
		}
	}

	if len(allKeys) == 0 {
		return nil, nil
	}

	// Join all keys with newlines
	return joinBytes(allKeys, []byte("\n")), nil
}

// LoadAuthorizedKeysMulti loads and aggregates authorized public keys from multiple sources.
// Similar to LoadTrustedUserCAKeysMulti but for authorized_keys.
func LoadAuthorizedKeysMulti(files, base64Data ListOrString, vaultPath string, vars map[string]string, baseDir string) ([]byte, error) {
	var allKeys [][]byte

	// Load from files and base64 data
	if files.Any() || base64Data.Any() {
		keys, err := LoadFileOrBase64Many(files, base64Data, vars, baseDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load authorized keys from files/data: %w", err)
		}
		if len(keys) > 0 {
			allKeys = append(allKeys, keys)
		}
	}

	// Load from Vault if path provided
	if vaultPath != "" {
		vaultKeys, err := GetVaultFieldAny(vaultPath, []string{"authorized_keys", "public_key", "ssh_key", "key"})
		if err != nil {
			return nil, fmt.Errorf("failed to load authorized keys from Vault: %w", err)
		}
		if len(vaultKeys) > 0 {
			allKeys = append(allKeys, vaultKeys)
		}
	}

	if len(allKeys) == 0 {
		return nil, nil
	}

	return joinBytes(allKeys, []byte("\n")), nil
}

// LoadPrivateKeyFromVaultOrFile loads a private key from Vault or from file/base64.
// Vault is tried first if vaultPath is provided.
func LoadPrivateKeyFromVaultOrFile(vaultPath, keyFile, keyData string, vars map[string]string, baseDir string) ([]byte, error) {
	// Try Vault first if path provided
	if vaultPath != "" {
		key, err := GetVaultFieldAny(vaultPath, []string{"private_key", "key", "ssh_key"})
		if err == nil && len(key) > 0 {
			return key, nil
		}
		// Log but don't fail - fall through to file/data
	}

	// Fall back to file or base64 data
	return LoadFileOrBase64(keyFile, keyData, vars, baseDir)
}

// joinBytes joins byte slices with a separator (helper function)
func joinBytes(slices [][]byte, sep []byte) []byte {
	if len(slices) == 0 {
		return nil
	}
	if len(slices) == 1 {
		return slices[0]
	}
	n := len(sep) * (len(slices) - 1)
	for _, s := range slices {
		n += len(s)
	}
	result := make([]byte, n)
	bp := copy(result, slices[0])
	for _, s := range slices[1:] {
		bp += copy(result[bp:], sep)
		bp += copy(result[bp:], s)
	}
	return result
}
