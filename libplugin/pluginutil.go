// Package libplugin: Plugin Utility Helpers for SSHPiper Plugins
//
// Provides helpers for authentication method name conversion, plugin logging configuration, and Upstream auth constructors for SSHPiper plugins.
//
// # Features
//   - AuthMethodName/AuthMethodFromName: Convert between AuthMethod enums and string names
//   - PluginLogrusConfig: Sets up logrus logging for plugins
//   - Auth*Create helpers: Constructors for Upstream auth types (password, private key, remote signer, etc.)
//
// # Usage Example
//
//	method := libplugin.AuthMethodName(libplugin.AuthMethod_PASSWORD)
//	auth := libplugin.AuthPasswordCreate([]byte("secret"))
package libplugin

import (
	"io"

	"github.com/sirupsen/logrus"
)

// AuthMethodName returns the string name for an AuthMethod enum value.
func AuthMethodName(a AuthMethod) string {
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

// AuthMethodFromName returns the AuthMethod enum value for a string name.
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

// PluginLogrusConfig sets up logrus logging for a plugin using the provided formatter and logger.
//
// Example:
//
//	plibplugin.PluginLogrusConfig(plugin, &logrus.TextFormatter{}, nil)
func PluginLogrusConfig(p PluginServer, formatter logrus.Formatter, logger *logrus.Logger) {
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

// AuthNoneCreate returns an Upstream_None with an empty UpstreamNoneAuth.
func AuthNoneCreate() *Upstream_None {
	return &Upstream_None{
		None: &UpstreamNoneAuth{},
	}
}

// AuthPasswordCreate returns an Upstream_Password with the given password.
func AuthPasswordCreate(password []byte) *Upstream_Password {
	return AuthPasswordCreateFromString(string(password))
}

// AuthPasswordCreateFromString returns an Upstream_Password with the given password string.
func AuthPasswordCreateFromString(password string) *Upstream_Password {
	return &Upstream_Password{
		Password: &UpstreamPasswordAuth{
			Password: password,
		},
	}
}

// AuthPrivateKeyCreate returns an Upstream_PrivateKey with the given private key and optional CA public key.
func AuthPrivateKeyCreate(key []byte, optionalSignedCaPublicKey ...[]byte) *Upstream_PrivateKey {
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

// AuthRemoteSignerCreate returns an Upstream_RemoteSigner with the given meta string.
func AuthRemoteSignerCreate(meta string) *Upstream_RemoteSigner {
	return &Upstream_RemoteSigner{
		RemoteSigner: &UpstreamRemoteSignerAuth{
			Meta: meta,
		},
	}
}

// AuthNextPluginCreate returns an Upstream_NextPlugin with the given meta map.
func AuthNextPluginCreate(meta map[string]string) *Upstream_NextPlugin {
	return &Upstream_NextPlugin{
		NextPlugin: &UpstreamNextPluginAuth{
			Meta: meta,
		},
	}
}

// AuthRetryCurrentPluginCreate returns an Upstream_RetryCurrentPlugin with the given meta map.
func AuthRetryCurrentPluginCreate(meta map[string]string) *Upstream_RetryCurrentPlugin {
	return &Upstream_RetryCurrentPlugin{
		RetryCurrentPlugin: &UpstreamRetryCurrentPluginAuth{
			Meta: meta,
		},
	}
}
