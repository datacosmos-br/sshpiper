package libplugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// MetadataKeyCAFingerprint is the ConnMeta.Metadata key under which sshpiperd
// publishes the SHA256 fingerprint of the CA that issued the client's SSH
// certificate. Plugins can route on this value without parsing the public key
// blob themselves. The key is absent when the offered key is not a certificate.
const MetadataKeyCAFingerprint = "ca-fingerprint"

// CertCAFingerprint parses a marshaled SSH public key and, when it is a
// certificate, returns the SHA256 fingerprint of the issuing CA
// (Certificate.SignatureKey). It returns an empty string (no error) when the
// key is a plain public key rather than a certificate.
func CertCAFingerprint(marshaledPublicKey []byte) (string, error) {
	pub, err := ssh.ParsePublicKey(marshaledPublicKey)
	if err != nil {
		return "", err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return "", nil
	}
	return ssh.FingerprintSHA256(cert.SignatureKey), nil
}

func AuthMethodTypeToName(a AuthMethod) string {
	switch a {
	case AuthMethod_NONE:
		return "none"
	case AuthMethod_PASSWORD:
		return "password"
	case AuthMethod_PUBLICKEY:
		return "publickey"
	case AuthMethod_KEYBOARD_INTERACTIVE:
		return "keyboard-interactive"
	}
	return ""
}

func AuthMethodFromName(n string) AuthMethod {
	switch n {
	case "none":
		return AuthMethod_NONE
	case "password":
		return AuthMethod_PASSWORD
	case "publickey":
		return AuthMethod_PUBLICKEY
	case "keyboard-interactive":
		return AuthMethod_KEYBOARD_INTERACTIVE
	}
	return -1
}

func ConfigStdioLogrus(p SshPiperPlugin, formatter logrus.Formatter, logger *logrus.Logger) {
	if logger == nil {
		logger = logrus.StandardLogger()
	}

	p.SetConfigLoggerCallback(func(w io.Writer, level string, tty bool) {
		logger.SetOutput(w)
		lv, _ := logrus.ParseLevel(level)
		logger.SetLevel(lv)

		if formatter != nil {
			logger.SetFormatter(formatter)
		}

		if tty {
			if formatter == nil {
				logger.SetFormatter(&logrus.TextFormatter{ForceColors: true})
			}
		}
	})
}

// SplitHostPortForSSH is the modified version of net.SplitHostPort but return port 22 is no port is specified
func SplitHostPortForSSH(addr string) (host string, port int, err error) {
	host = addr
	h, p, err := net.SplitHostPort(host)
	if err == nil {
		host = h
		var parsedPort int64
		parsedPort, err = strconv.ParseInt(p, 10, 32)
		if err != nil {
			return
		}
		port = int(parsedPort)
	} else if host != "" {
		// test valid after concat :22
		if _, _, err = net.SplitHostPort(host + ":22"); err == nil {
			port = 22
		}
	}

	if host == "" {
		err = fmt.Errorf("empty addr")
	}

	return
}

// DialForSSH is the modified version of net.Dial, would add ":22" automaticlly
func DialForSSH(addr string) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil && addr != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(addr + ":22"); err == nil {
			addr += ":22"
		}
	}

	return net.Dial("tcp", addr)
}

func CreateNoneAuth() *Upstream_None {
	return &Upstream_None{
		None: &UpstreamNoneAuth{},
	}
}

func CreatePasswordAuth(password []byte) *Upstream_Password {
	return CreatePasswordAuthFromString(string(password))
}

func CreatePasswordAuthFromString(password string) *Upstream_Password {
	return &Upstream_Password{
		Password: &UpstreamPasswordAuth{
			Password: password,
		},
	}
}

func CreatePrivateKeyAuth(key []byte, optionalSignedCaPublicKey ...[]byte) *Upstream_PrivateKey {
	var caPublicKey []byte
	if len(optionalSignedCaPublicKey) > 0 {
		caPublicKey = optionalSignedCaPublicKey[0]
	}
	return &Upstream_PrivateKey{
		PrivateKey: &UpstreamPrivateKeyAuth{
			PrivateKey:  key,
			CaPublicKey: caPublicKey,
		},
	}
}

func CreateRemoteSignerAuth(meta string) *Upstream_RemoteSigner {
	return &Upstream_RemoteSigner{
		RemoteSigner: &UpstreamRemoteSignerAuth{
			Meta: meta,
		},
	}
}

func CreateNextPluginAuth(meta map[string]string) *Upstream_NextPlugin {
	return &Upstream_NextPlugin{
		NextPlugin: &UpstreamNextPluginAuth{
			Meta: meta,
		},
	}
}

func CreateRetryCurrentPluginAuth(meta map[string]string) *Upstream_RetryCurrentPlugin {
	return &Upstream_RetryCurrentPlugin{
		RetryCurrentPlugin: &UpstreamRetryCurrentPluginAuth{
			Meta: meta,
		},
	}
}

// ListOrString is a helper for YAML fields that can be a string or a list of strings.
// This allows flexible configuration where users can specify either:
//
//	field: "single_value"
//
// or:
//
//	field:
//	  - "value1"
//	  - "value2"
type ListOrString struct {
	List []string
	Str  string
}

// UnmarshalYAML implements yaml.Unmarshaler to support both string and []string for ListOrString.
func (l *ListOrString) UnmarshalYAML(unmarshal func(any) error) error {
	// Try as []string
	var list []string
	if err := unmarshal(&list); err == nil {
		l.List = list
		l.Str = ""
		return nil
	}
	// Try as string
	var single string
	if err := unmarshal(&single); err == nil {
		l.List = nil
		l.Str = single
		return nil
	}
	return fmt.Errorf("ListOrString: value is neither string nor []string")
}

// Any returns true if the ListOrString contains any value.
func (l *ListOrString) Any() bool {
	return len(l.List) > 0 || l.Str != ""
}

// Combine returns all values as a single slice.
// If Str is set, it is appended to the List.
func (l *ListOrString) Combine() []string {
	if l.Str != "" {
		return append(l.List, l.Str)
	}
	return l.List
}

// LoadFileOrBase64 loads data from a file (with variable expansion and relative to baseDir)
// or from a base64-encoded string.
//
// Parameters:
//   - file: Path to file (supports ${VAR} expansion using vars map and environment)
//   - base64data: Base64-encoded data string
//   - vars: Map of variables for path expansion
//   - baseDir: Base directory for resolving relative paths
//
// If both file and base64data are empty, returns nil, nil.
// If file is not empty, expands variables using vars, resolves relative to baseDir, and loads the file.
// If base64data is not empty, decodes the base64 string.
// Returns an error if loading or decoding fails.
func LoadFileOrBase64(file string, base64data string, vars map[string]string, baseDir string) ([]byte, error) {
	if file != "" {
		file = os.Expand(file, func(placeholderName string) string {
			if v, ok := vars[placeholderName]; ok {
				return v
			}
			return os.Getenv(placeholderName)
		})
		if !filepath.IsAbs(file) && baseDir != "" {
			file = filepath.Join(baseDir, file)
		}
		return os.ReadFile(file)
	}
	if base64data != "" {
		return base64.StdEncoding.DecodeString(base64data)
	}
	return nil, nil
}

// LoadFileOrBase64Many loads and joins data from multiple files and/or base64-encoded strings.
// Each file path is expanded and resolved relative to baseDir. All data is joined with a newline separator.
//
// This function is essential for loading multiple CA keys, authorized keys, or known hosts
// from various sources and combining them into a single byte slice.
//
// Returns an error if any file or base64 decoding fails.
func LoadFileOrBase64Many(files ListOrString, base64data ListOrString, vars map[string]string, baseDir string) ([]byte, error) {
	var byteSlices [][]byte
	for _, file := range files.Combine() {
		data, err := LoadFileOrBase64(file, "", vars, baseDir)
		if err != nil {
			return nil, err
		}
		if data != nil {
			byteSlices = append(byteSlices, data)
		}
	}
	for _, data := range base64data.Combine() {
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, err
		}
		if decoded != nil {
			byteSlices = append(byteSlices, decoded)
		}
	}
	return bytes.Join(byteSlices, []byte("\n")), nil
}
