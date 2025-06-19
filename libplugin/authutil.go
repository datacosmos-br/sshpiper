// Package libplugin: Authentication Utility Helpers for SSHPiper Plugins
//
// Provides helpers for password and public key authentication, htpasswd and Vault integration, and aggregation of authorized keys and CA keys for plugin implementations.
//
// # Features
//   - HtpasswdPasswordCheck: Checks a username and password against htpasswd data
//   - HtpasswdPasswordFieldsCheck: Checks a password against htpasswdData or htpasswdFile fields
//   - PasswordCheckFromSpecs: Checks a password against a slice of specs (htpasswd, file, Vault)
//   - UpstreamCreate: Constructs an Upstream from SkelPipeTo and optional password
//   - AuthorizedKeysAggregateFromSpecs: Aggregates authorized keys from specs
//   - TrustedUserCAKeysAggregateFromSpecs: Aggregates trusted CA keys from specs
//   - KubernetesSecretFieldLoad: Loads a field from a Kubernetes Secret
//   - VaultSecretFieldLoad: Loads a field from a Vault secret
//   - StringOrBase64Load: Decodes a base64 string or returns the raw string
//
// # Usage Example
//
//	ok, err := libplugin.HtpasswdPasswordCheck(htpasswdData, username, password)
//	ok, err := libplugin.HtpasswdPasswordFieldsCheck(htpasswdData, htpasswdFile, username, password)
//	ok, err := libplugin.PasswordCheckFromSpecs(specs, user, password)
//	up, err := libplugin.UpstreamCreate(sk, conn, to, password)
//	keys, err := libplugin.AuthorizedKeysAggregateFromSpecs(specs, conn)
//	caKeys, err := libplugin.TrustedUserCAKeysAggregateFromSpecs(specs, conn)

// CheckHtpasswdPassword checks a username and password against htpasswd data.
package libplugin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	sync "sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckHtpasswdPassword(htpasswdData []byte, username, password string) (bool, error) {
	auth, err := htpasswd.NewFromReader(bytes.NewReader(htpasswdData), htpasswd.DefaultSystems, nil)
	if err != nil {
		return false, err
	}
	return auth.Match(username, password), nil
}

// CheckHtpasswdPasswordFields checks a password against htpasswdData or htpasswdFile fields in a 'from' spec.
// Returns true if the password matches, false otherwise.
// Example usage:
//
//	ok, err := CheckHtpasswdPasswordFields(htpasswdData, htpasswdFile, username, password)
func CheckHtpasswdPasswordFields(htpasswdData, htpasswdFile string, username string, password []byte) (bool, error) {
	if htpasswdData != "" {
		data, err := base64.StdEncoding.DecodeString(htpasswdData)
		if err != nil {
			return false, err
		}
		return CheckHtpasswdPassword(data, username, string(password))
	}
	if htpasswdFile != "" {
		data, err := os.ReadFile(htpasswdFile)
		if err != nil {
			return false, err
		}
		return CheckHtpasswdPassword(data, username, string(password))
	}
	return false, nil
}

// CheckPasswordFromSpecs iterates over specs and uses CheckHtpasswdPasswordFields and Vault/secret fields.
// Supports htpasswd, file, and Vault sources.
// Returns true if any spec matches the password.
// Example usage:
//
//	ok, err := CheckPasswordFromSpecs(specs, user, password)
func CheckPasswordFromSpecs(specs []interface{}, user string, password []byte) (bool, error) {
	for _, spec := range specs {
		v := reflect.ValueOf(spec).Elem()
		htpasswdData := v.FieldByName("HtpasswdData").String()
		htpasswdFile := v.FieldByName("HtpasswdFile").String()
		vaultPath := ""
		if f := v.FieldByName("VaultKVPath"); f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
			vaultPath = f.String()
		}
		if vaultPath != "" {
			vaultData, err := GetVaultSecretField(vaultPath, "password")
			if err != nil {
				return false, fmt.Errorf("vault secret error: %w", err)
			}
			if string(vaultData) == string(password) {
				return true, nil
			}
		}
		ok, err := CheckHtpasswdPasswordFields(htpasswdData, htpasswdFile, user, password)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// PasswordCallback handles password authentication for the connection.
// Moved from skel.go.
func PasswordCallback(sk *SkelPlugin, conn PluginConnMetadata, password []byte) (*Upstream, error) {
	_, to, err := sk.match(conn, func(from SkelPipeFrom) (bool, error) {
		frompass, ok := from.(SkelPipeFromPassword)
		if !ok {
			return false, nil
		}
		return frompass.TestPassword(conn, password)
	})
	if err != nil {
		return nil, err
	}
	return CreateUpstream(sk, conn, to, password)
}

// PublicKeyCallback handles public key authentication for the connection.
// Moved from skel.go.
func PublicKeyCallback(sk *SkelPlugin, conn PluginConnMetadata, publicKey []byte) (*Upstream, error) {
	pubKey, err := ssh.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pkcert, isCert := pubKey.(*ssh.Certificate)
	if isCert {
		if pkcert.CertType != ssh.UserCert {
			return nil, fmt.Errorf("only user certificates are supported, cert type: %v", pkcert.CertType)
		}
		certChecker := ssh.CertChecker{}
		if err := certChecker.CheckCert(conn.User(), pkcert); err != nil {
			return nil, err
		}
	}
	_, to, err := sk.match(conn, func(from SkelPipeFrom) (bool, error) {
		fromPubKey, ok := from.(SkelPipeFromPublicKey)
		if !ok {
			return false, nil
		}
		verified := false
		if isCert {
			rest, err := fromPubKey.TrustedUserCAKeys(conn)
			if err != nil {
				return false, err
			}
			var trustedca ssh.PublicKey
			for len(rest) > 0 {
				trustedca, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					return false, err
				}
				if subtle.ConstantTimeCompare(trustedca.Marshal(), pkcert.SignatureKey.Marshal()) == 1 {
					verified = true
					break
				}
			}
		} else {
			rest, err := fromPubKey.AuthorizedKeys(conn)
			if err != nil {
				return false, err
			}
			var authedPubkey ssh.PublicKey
			for len(rest) > 0 {
				authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					return false, err
				}
				if subtle.ConstantTimeCompare(authedPubkey.Marshal(), publicKey) == 1 {
					verified = true
					break
				}
			}
		}
		return verified, nil
	})
	if err != nil {
		return nil, err
	}
	return CreateUpstream(sk, conn, to, nil)
}

// CreateUpstream constructs an Upstream from the SkelPipeTo and optional password.
// Moved from skel.go.
func CreateUpstream(sk *SkelPlugin, conn PluginConnMetadata, to SkelPipeTo, originalPassword []byte) (*Upstream, error) {
	host, port, err := SplitHostPortForSSH(to.Host(conn))
	if err != nil {
		return nil, err
	}
	user := to.User(conn)
	if user == "" {
		user = conn.User()
	}
	sk.cache.SetDefault(conn.UniqueID(), to)
	u := &Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      user,
		IgnoreHostKey: to.IgnoreHostKey(conn),
	}
	switch to := to.(type) {
	case SkelPipeToPassword:
		overridepassword, err := to.OverridePassword(conn)
		if err != nil {
			return nil, err
		}
		if overridepassword != nil {
			u.Auth = AuthPasswordCreate(overridepassword)
		} else {
			u.Auth = AuthPasswordCreate(originalPassword)
		}
	case SkelPipeToPrivateKey:
		priv, cert, err := to.PrivateKey(conn)
		if err != nil {
			return nil, err
		}
		u.Auth = AuthPrivateKeyCreate(priv, cert)
	default:
		return nil, fmt.Errorf("pipe to does not support any auth method")
	}
	return u, err
}

// AggregateAuthorizedKeysFromSpecs loads and aggregates all authorized public keys from a slice of 'from' specs.
// Returns a single blob of authorized keys.
// Example usage:
//
//	keys, err := AggregateAuthorizedKeysFromSpecs(specs, conn)
func AggregateAuthorizedKeysFromSpecs(specs []interface{}, conn PluginConnMetadata) ([]byte, error) {
	return AggregateKeysFromSpecs(
		specs,
		[]string{"AuthorizedKeysFile"},
		[]string{"AuthorizedKeysData"},
		map[string]string{"DOWNSTREAM_USER": conn.User()},
		"/",
		"ssh-key",
	)
}

// AggregateTrustedUserCAKeysFromSpecs loads and aggregates all trusted CA public keys from a slice of 'from' specs.
// Returns a single blob of CA keys.
// Example usage:
//
//	caKeys, err := AggregateTrustedUserCAKeysFromSpecs(specs, conn)
func AggregateTrustedUserCAKeysFromSpecs(specs []interface{}, conn PluginConnMetadata) ([]byte, error) {
	return AggregateKeysFromSpecs(
		specs,
		[]string{"TrustedUserCAKeysFile"},
		[]string{"TrustedUserCAKeysData"},
		map[string]string{"DOWNSTREAM_USER": conn.User()},
		"/",
		"ca-key",
	)
}

// GetAllAuthorizedKeysFromSpecs loads and aggregates all authorized public keys from a slice of 'from' specs.
// Moved from skelpipe.go.
func GetAllAuthorizedKeysFromSpecs(specs []interface{}, conn PluginConnMetadata) ([]byte, error) {
	return AggregateKeysFromSpecs(
		specs,
		[]string{"AuthorizedKeysFile"},
		[]string{"AuthorizedKeysData"},
		map[string]string{"DOWNSTREAM_USER": conn.User()},
		"/",
		"ssh-key",
	)
}

// GetAllTrustedUserCAKeysFromSpecs loads and aggregates all trusted CA public keys from a slice of 'from' specs.
// Moved from skelpipe.go.
func GetAllTrustedUserCAKeysFromSpecs(specs []interface{}, conn PluginConnMetadata) ([]byte, error) {
	return AggregateKeysFromSpecs(
		specs,
		[]string{"TrustedUserCAKeysFile"},
		[]string{"TrustedUserCAKeysData"},
		map[string]string{"DOWNSTREAM_USER": conn.User()},
		"/",
		"ca-key",
	)
}

// AggregateKeysFromSpecs collects and joins keys/CA keys from a slice of specs.
// It supports loading from multiple files, base64, and Vault/secret fields per spec.
//
// specs: slice of pointers to spec structs
// keyFileFields/keyDataFields: ordered list of possible field names for file/data (string or ListOrString)
// vars: variable map for expansion
// baseDir: base directory for relative file paths
// vaultField: the field name to use for Vault secret lookup (e.g., "ssh-key", "ca-key")
func AggregateKeysFromSpecs(specs []interface{}, keyFileFields, keyDataFields []string, vars map[string]string, baseDir string, vaultField string) ([]byte, error) {
	var all [][]byte
	for _, spec := range specs {
		v := reflect.ValueOf(spec).Elem()
		// Load all files
		for _, f := range keyFileFields {
			fv := v.FieldByName(f)
			if fv.IsValid() {
				switch fv.Kind() {
				case reflect.String:
					if fv.String() != "" {
						data, err := LoadFileOrBase64(fv.String(), "", vars, baseDir)
						if err != nil {
							return nil, err
						}
						if len(data) > 0 {
							all = append(all, data)
						}
					}
				case reflect.Struct:
					if fv.Type().Name() == "ListOrString" {
						los := fv.Interface().(ListOrString)
						data, err := LoadFileOrBase64Many(los, ListOrString{}, vars, baseDir)
						if err != nil {
							return nil, err
						}
						if len(data) > 0 {
							all = append(all, data)
						}
					}
				}
			}
		}
		// Load all data fields
		for _, f := range keyDataFields {
			fv := v.FieldByName(f)
			if fv.IsValid() {
				switch fv.Kind() {
				case reflect.String:
					if fv.String() != "" {
						decoded, err := base64.StdEncoding.DecodeString(fv.String())
						if err != nil {
							return nil, err
						}
						if len(decoded) > 0 {
							all = append(all, decoded)
						}
					}
				case reflect.Struct:
					if fv.Type().Name() == "ListOrString" {
						los := fv.Interface().(ListOrString)
						for _, s := range los.Combine() {
							decoded, err := base64.StdEncoding.DecodeString(s)
							if err != nil {
								return nil, err
							}
							if len(decoded) > 0 {
								all = append(all, decoded)
							}
						}
					}
				}
			}
		}
		// Vault
		if f := v.FieldByName("VaultKVPath"); f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
			vaultPath := f.String()
			vaultData, err := GetVaultSecretField(vaultPath, vaultField)
			if err != nil {
				return nil, fmt.Errorf("vault secret error: %w", err)
			}
			if len(vaultData) > 0 {
				all = append(all, vaultData)
			}
		}
	}
	return bytes.Join(all, []byte("\n")), nil
}

// LoadKubernetesSecretField loads the first found field from a Kubernetes Secret.
// fieldNames is a priority-ordered list of field names to try.
// Returns the value of the first found field, or an error if none found.
func LoadKubernetesSecretField(namespace, secretName string, fieldNames []string, k8sclient kubernetes.Interface) ([]byte, error) {
	secret, err := k8sclient.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	for _, k := range fieldNames {
		if data, ok := secret.Data[k]; ok && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("no matching field found in secret %s/%s", namespace, secretName)
}

// LoadVaultSecretField loads the first found field from a Vault secret at the given path.
// fieldNames is a priority-ordered list of field names to try.
// Returns the value of the first found field, or an error if none found.
func LoadVaultSecretField(path string, fieldNames []string) ([]byte, error) {
	secretData, err := GetSecret(path)
	if err != nil {
		return nil, err
	}
	for _, k := range fieldNames {
		if v, ok := secretData[k].(string); ok && v != "" {
			return []byte(v), nil
		}
	}
	return nil, fmt.Errorf("no matching field found in Vault secret at %s", path)
}

// LoadStringOrBase64 decodes a base64 string or returns the raw string as []byte.
func LoadStringOrBase64(data string) ([]byte, error) {
	if data == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err == nil {
		return decoded, nil
	}
	// Not base64, treat as raw
	return []byte(data), nil
}

// KeyboardInteractiveCallback is a placeholder for keyboard-interactive authentication support.
// Plugins can implement this to support challenge/response authentication.
// Example usage:
//
//	answer, err := KeyboardInteractiveCallback(user, instruction, question, echo)
//
// Not implemented by default.
var KeyboardInteractiveCallback func(user, instruction, question string, echo bool) (string, error)

// FlexibleFieldLookup returns the value of the first non-empty field from a struct, by name, supporting both string and ListOrString fields.
// Used for annotation-driven field selection in plugins.
// Example usage:
//
//	val, err := FlexibleFieldLookup(spec, []string{"PasswordField", "password"})
func FlexibleFieldLookup(spec interface{}, fieldNames []string) (string, error) {
	v := reflect.ValueOf(spec).Elem()
	for _, fname := range fieldNames {
		f := v.FieldByName(fname)
		if !f.IsValid() {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			if f.String() != "" {
				return f.String(), nil
			}
		case reflect.Struct:
			if f.Type().Name() == "ListOrString" {
				los := f.Interface().(ListOrString)
				for _, s := range los.Combine() {
					if s != "" {
						return s, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("no non-empty field found in %+v", fieldNames)
}

// NewVaultClient creates a new Vault client using environment variables VAULT_ADDR and VAULT_TOKEN.
// Returns an error if configuration is missing or invalid.
// Security: Ensure VAULT_TOKEN is not leaked or logged.
// Example usage:
//
//	client, err := NewVaultClient()
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

// getSecret retrieves a secret from the given path in Vault.
// The returned map contains the secret data.
// Example usage:
//
//	data, err := getSecret("secret/data/mykey")
func getSecret(path string) (map[string]interface{}, error) {
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
	secretData map[string]interface{}
	expiry     time.Time
}

// GetSecret retrieves and caches a Vault secret at the given path.
// Uses a global cache with configurable expiry (VAULT_CACHE_DURATION).
// Example usage:
//
//	data, err := GetSecret("secret/data/mykey")
func GetSecret(path string) (map[string]interface{}, error) {
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
// Returns the field as []byte, or error if not found or not a string.
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
// Returns the field as []byte, or error if none found.
func GetVaultFieldAny(path string, fieldNames []string) ([]byte, error) {
	for _, field := range fieldNames {
		val, err := GetVaultSecretField(path, field)
		if err == nil && len(val) > 0 {
			return val, nil
		}
	}
	return nil, fmt.Errorf("no matching field found in Vault secret at %s", path)
}

// GetFirstFieldFromSpecs returns the first non-empty value from Vault or fields in specs.
// vaultFieldNames: field names to try in Vault
// fileFieldNames: field names to try for file/base64
// dataFieldNames: field names to try for base64 data
// Returns the first found value, or nil if none found.
func GetFirstFieldFromSpecs(
	specs []interface{},
	vaultFieldNames []string,
	fileFieldNames []string,
	dataFieldNames []string,
	conn PluginConnMetadata,
	baseDir string,
) ([]byte, error) {
	for _, spec := range specs {
		v := reflect.ValueOf(spec).Elem()
		if f := v.FieldByName("VaultKVPath"); f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
			vaultPath := f.String()
			val, err := GetVaultFieldAny(vaultPath, vaultFieldNames)
			if err == nil && len(val) > 0 {
				return val, nil
			}
		}
		// Try file/base64 fields
		for _, fName := range fileFieldNames {
			f := v.FieldByName(fName)
			if f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
				data, err := LoadFileOrBase64(f.String(), "", map[string]string{"DOWNSTREAM_USER": conn.User()}, baseDir)
				if err == nil && len(data) > 0 {
					return data, nil
				}
			}
			if f.IsValid() && f.Type().Name() == "ListOrString" {
				los := f.Interface().(ListOrString)
				data, err := LoadFileOrBase64Many(los, ListOrString{}, map[string]string{"DOWNSTREAM_USER": conn.User()}, baseDir)
				if err == nil && len(data) > 0 {
					return data, nil
				}
			}
		}
		for _, dName := range dataFieldNames {
			f := v.FieldByName(dName)
			if f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
				decoded, err := base64.StdEncoding.DecodeString(f.String())
				if err == nil && len(decoded) > 0 {
					return decoded, nil
				}
			}
			if f.IsValid() && f.Type().Name() == "ListOrString" {
				los := f.Interface().(ListOrString)
				for _, s := range los.Combine() {
					decoded, err := base64.StdEncoding.DecodeString(s)
					if err == nil && len(decoded) > 0 {
						return decoded, nil
					}
				}
			}
		}
	}
	return nil, nil
}

// AggregateFieldsFromSpecs aggregates all values from Vault or fields in specs.
// Returns a single blob of all found values, joined by newlines.
func AggregateFieldsFromSpecs(
	specs []interface{},
	vaultFieldNames []string,
	fileFieldNames []string,
	dataFieldNames []string,
	conn PluginConnMetadata,
	baseDir string,
) ([]byte, error) {
	var all [][]byte
	for _, spec := range specs {
		v := reflect.ValueOf(spec).Elem()
		if f := v.FieldByName("VaultKVPath"); f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
			vaultPath := f.String()
			val, err := GetVaultFieldAny(vaultPath, vaultFieldNames)
			if err == nil && len(val) > 0 {
				all = append(all, val)
			}
		}
		for _, fName := range fileFieldNames {
			f := v.FieldByName(fName)
			if f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
				data, err := LoadFileOrBase64(f.String(), "", map[string]string{"DOWNSTREAM_USER": conn.User()}, baseDir)
				if err == nil && len(data) > 0 {
					all = append(all, data)
				}
			}
			if f.IsValid() && f.Type().Name() == "ListOrString" {
				los := f.Interface().(ListOrString)
				data, err := LoadFileOrBase64Many(los, ListOrString{}, map[string]string{"DOWNSTREAM_USER": conn.User()}, baseDir)
				if err == nil && len(data) > 0 {
					all = append(all, data)
				}
			}
		}
		for _, dName := range dataFieldNames {
			f := v.FieldByName(dName)
			if f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
				decoded, err := base64.StdEncoding.DecodeString(f.String())
				if err == nil && len(decoded) > 0 {
					all = append(all, decoded)
				}
			}
			if f.IsValid() && f.Type().Name() == "ListOrString" {
				los := f.Interface().(ListOrString)
				for _, s := range los.Combine() {
					decoded, err := base64.StdEncoding.DecodeString(s)
					if err == nil && len(decoded) > 0 {
						all = append(all, decoded)
					}
				}
			}
		}
	}
	return bytes.Join(all, []byte("\n")), nil
}
