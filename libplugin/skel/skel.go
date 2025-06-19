<<<<<<< HEAD:libplugin/skel.go
// Package libplugin provides the SkelPlugin skeleton and interfaces for generic SSHPiper plugin implementations.
//
// This file contains:
//   - SkelPlugin: Generic, cache-enabled plugin skeleton for SSHPiper plugins
//   - SkelPipe, SkelPipeFrom, SkelPipeTo and their sub-interfaces for password/publickey/privatekey
//   - All generic plugin callback logic (method selection, host key verification, password/publickey callbacks, upstream construction)
//
// These types and functions are used by plugins to implement the SkelPlugin contract, enabling flexible, reusable plugin logic for authentication and connection handling.
//
// Example usage:
//
//	skel := NewSkelPlugin(listPipeFn)
//	config := skel.CreateConfig()
package libplugin
=======
package skel
>>>>>>> upstream/master:libplugin/skel/skel.go

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/patrickmn/go-cache"
<<<<<<< HEAD:libplugin/skel.go
=======
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
>>>>>>> upstream/master:libplugin/skel/skel.go

	log "github.com/sirupsen/logrus"
)

// SkelPlugin is a generic, cache-enabled plugin skeleton for SSHPiper plugins.
//
// Example usage:
//
//	skel := NewSkelPlugin(listPipeFn)
//	config := skel.CreateConfig()
type SkelPlugin struct {
	cache    *cache.Cache
<<<<<<< HEAD:libplugin/skel.go
	listPipe func(PluginConnMetadata) ([]SkelPipe, error)
}

// NewSkelPlugin creates a new SkelPlugin with the given listPipe function.
//
// Example usage:
//
//	skel := NewSkelPlugin(listPipeFn)
func NewSkelPlugin(listPipe func(PluginConnMetadata) ([]SkelPipe, error)) *SkelPlugin {
=======
	listPipe func(libplugin.ConnMetadata) ([]SkelPipe, error)
}

func NewSkelPlugin(listPipe func(libplugin.ConnMetadata) ([]SkelPipe, error)) *SkelPlugin {
>>>>>>> upstream/master:libplugin/skel/skel.go
	return &SkelPlugin{
		cache:    cache.New(1*time.Minute, 10*time.Minute),
		listPipe: listPipe,
	}
}

// SkelPipe represents a plugin pipe with one or more SkelPipeFrom entries.
//
// Example usage:
//
//	pipes, err := plugin.listPipe(conn)
type SkelPipe interface {
	From() []SkelPipeFrom
}

// SkelPipeFrom represents a source for matching a downstream connection.
//
// Example usage:
//
//	to, err := from.MatchConn(conn)
type SkelPipeFrom interface {
<<<<<<< HEAD:libplugin/skel.go
	MatchConn(conn PluginConnMetadata) (SkelPipeTo, error)
=======
	MatchConn(conn libplugin.ConnMetadata) (SkelPipeTo, error)
>>>>>>> upstream/master:libplugin/skel/skel.go
}

// SkelPipeFromPassword is a SkelPipeFrom that supports password authentication.
//
// Example usage:
//
//	ok, err := from.TestPassword(conn, password)
type SkelPipeFromPassword interface {
	SkelPipeFrom
<<<<<<< HEAD:libplugin/skel.go
	TestPassword(conn PluginConnMetadata, password []byte) (bool, error)
=======

	TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error)
>>>>>>> upstream/master:libplugin/skel/skel.go
}

// SkelPipeFromPublicKey is a SkelPipeFrom that supports public key authentication.
//
// Example usage:
//
//	keys, err := from.AuthorizedKeys(conn)
type SkelPipeFromPublicKey interface {
	SkelPipeFrom
<<<<<<< HEAD:libplugin/skel.go
	AuthorizedKeys(conn PluginConnMetadata) ([]byte, error)
	TrustedUserCAKeys(conn PluginConnMetadata) ([]byte, error)
=======

	AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error)
	TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error)
>>>>>>> upstream/master:libplugin/skel/skel.go
}

// SkelPipeTo represents an upstream connection target.
//
// Example usage:
//
//	host := to.Host(conn)
type SkelPipeTo interface {
<<<<<<< HEAD:libplugin/skel.go
	Host(conn PluginConnMetadata) string
	User(conn PluginConnMetadata) string
	IgnoreHostKey(conn PluginConnMetadata) bool
	KnownHosts(conn PluginConnMetadata) ([]byte, error)
=======
	Host(conn libplugin.ConnMetadata) string
	User(conn libplugin.ConnMetadata) string
	IgnoreHostKey(conn libplugin.ConnMetadata) bool
	KnownHosts(conn libplugin.ConnMetadata) ([]byte, error)
>>>>>>> upstream/master:libplugin/skel/skel.go
}

// SkelPipeToPassword is a SkelPipeTo that supports password override.
//
// Example usage:
//
//	pass, err := to.OverridePassword(conn)
type SkelPipeToPassword interface {
	SkelPipeTo
<<<<<<< HEAD:libplugin/skel.go
	OverridePassword(conn PluginConnMetadata) ([]byte, error)
=======

	OverridePassword(conn libplugin.ConnMetadata) ([]byte, error)
>>>>>>> upstream/master:libplugin/skel/skel.go
}

// SkelPipeToPrivateKey is a SkelPipeTo that supports private key authentication.
//
// Example usage:
//
//	priv, cert, err := to.PrivateKey(conn)
type SkelPipeToPrivateKey interface {
	SkelPipeTo
<<<<<<< HEAD:libplugin/skel.go
	PrivateKey(conn PluginConnMetadata) ([]byte, []byte, error)
}

// CreateConfig returns a PluginConfig with SkelPlugin's callbacks.
//
// Example usage:
//
//	config := skel.CreateConfig()
func (p *SkelPlugin) CreateConfig() *PluginConfig {
	return &PluginConfig{
=======

	PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error)
}

func (p *SkelPlugin) CreateConfig() *libplugin.SshPiperPluginConfig {
	return &libplugin.SshPiperPluginConfig{
>>>>>>> upstream/master:libplugin/skel/skel.go
		NextAuthMethodsCallback: p.SupportedMethods,
		PasswordCallback:        p.PasswordCallback,
		PublicKeyCallback:       p.PublicKeyCallback,
		VerifyHostKeyCallback:   p.VerifyHostKeyCallback,
	}
}

<<<<<<< HEAD:libplugin/skel.go
// SupportedMethods returns the supported authentication methods for a connection.
//
// Example usage:
//
//	methods, err := skel.SupportedMethods(conn)
func (p *SkelPlugin) SupportedMethods(conn PluginConnMetadata) ([]string, error) {
=======
func (p *SkelPlugin) SupportedMethods(conn libplugin.ConnMetadata) ([]string, error) {
>>>>>>> upstream/master:libplugin/skel/skel.go
	set := make(map[string]bool)

	pipes, err := p.listPipe(conn)
	if err != nil {
		return nil, err
	}

	for _, pipe := range pipes {
		for _, from := range pipe.From() {

			switch from.(type) {
			case SkelPipeFromPublicKey:
				set["publickey"] = true
			default:
				set["password"] = true
			}

			if len(set) == 2 {
				break
			}
		}
	}

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}

	return methods, nil
}

<<<<<<< HEAD:libplugin/skel.go
// VerifyHostKeyCallback verifies the upstream host key using the cached SkelPipeTo.
//
// Example usage:
//
//	err := skel.VerifyHostKeyCallback(conn, hostname, netaddr, key)
func (p *SkelPlugin) VerifyHostKeyCallback(conn PluginConnMetadata, hostname, netaddr string, key []byte) error {
=======
func (p *SkelPlugin) VerifyHostKeyCallback(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
>>>>>>> upstream/master:libplugin/skel/skel.go
	item, found := p.cache.Get(conn.UniqueID())
	if !found {
		log.Warnf("connection expired when verifying host key for conn [%v]", conn.UniqueID())
		return fmt.Errorf("connection expired")
	}

	to := item.(SkelPipeTo)

	data, err := to.KnownHosts(conn)
	if err != nil {
		return err
	}

	return VerifyHostKeyFromKnownHosts(bytes.NewBuffer(data), hostname, netaddr, key)
}

<<<<<<< HEAD:libplugin/skel.go
// match finds a matching SkelPipeFrom and SkelPipeTo for the connection, using the provided verify function.
//
// Example usage:
//
//	from, to, err := skel.match(conn, verifyFn)
func (p *SkelPlugin) match(conn PluginConnMetadata, verify func(SkelPipeFrom) (bool, error)) (SkelPipeFrom, SkelPipeTo, error) {
=======
func (p *SkelPlugin) match(conn libplugin.ConnMetadata, verify func(SkelPipeFrom) (bool, error)) (SkelPipeFrom, SkelPipeTo, error) {
>>>>>>> upstream/master:libplugin/skel/skel.go
	pipes, err := p.listPipe(conn)
	if err != nil {
		return nil, nil, err
	}

	for _, pipe := range pipes {
		for _, from := range pipe.From() {

			to, err := from.MatchConn(conn)
			if err != nil {
				return nil, nil, err
			}

			if to == nil {
				continue
			}

			ok, err := verify(from)
			if err != nil {
				return nil, nil, err
			}

			if ok {
				return from, to, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no matching pipe for username [%v] found", conn.User())
}

<<<<<<< HEAD:libplugin/skel.go
// PasswordCallback handles password authentication for the connection.
//
// Example usage:
//
//	up, err := skel.PasswordCallback(conn, password)
func (p *SkelPlugin) PasswordCallback(conn PluginConnMetadata, password []byte) (*Upstream, error) {
	return PasswordCallback(p, conn, password)
}

// PublicKeyCallback handles public key authentication for the connection.
//
// Example usage:
//
//	up, err := skel.PublicKeyCallback(conn, publicKey)
func (p *SkelPlugin) PublicKeyCallback(conn PluginConnMetadata, publicKey []byte) (*Upstream, error) {
	return PublicKeyCallback(p, conn, publicKey)
=======
func (p *SkelPlugin) PasswordCallback(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	_, to, err := p.match(conn, func(from SkelPipeFrom) (bool, error) {
		frompass, ok := from.(SkelPipeFromPassword)

		if !ok {
			return false, nil
		}

		return frompass.TestPassword(conn, password)
	})
	if err != nil {
		return nil, err
	}

	u, err := p.createUpstream(conn, to, password)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (p *SkelPlugin) PublicKeyCallback(conn libplugin.ConnMetadata, publicKey []byte) (*libplugin.Upstream, error) {
	pubKey, err := ssh.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pkcert, isCert := pubKey.(*ssh.Certificate)
	if isCert {
		// ensure cert is valid first

		if pkcert.CertType != ssh.UserCert {
			return nil, fmt.Errorf("only user certificates are supported, cert type: %v", pkcert.CertType)
		}

		certChecker := ssh.CertChecker{}
		if err := certChecker.CheckCert(conn.User(), pkcert); err != nil {
			return nil, err
		}
	}

	_, to, err := p.match(conn, func(from SkelPipeFrom) (bool, error) {
		// verify public key
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

	u, err := p.createUpstream(conn, to, nil)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (p *SkelPlugin) createUpstream(conn libplugin.ConnMetadata, to SkelPipeTo, originalPassword []byte) (*libplugin.Upstream, error) {
	host, port, err := libplugin.SplitHostPortForSSH(to.Host(conn))
	if err != nil {
		return nil, err
	}

	user := to.User(conn)
	if user == "" {
		user = conn.User()
	}

	p.cache.SetDefault(conn.UniqueID(), to)

	u := &libplugin.Upstream{
		Host:          host,
		Port:          int32(port), // port is already checked to be within int32 range in SplitHostPortForSSH
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
			u.Auth = libplugin.CreatePasswordAuth(overridepassword)
		} else {
			u.Auth = libplugin.CreatePasswordAuth(originalPassword)
		}

	case SkelPipeToPrivateKey:
		priv, cert, err := to.PrivateKey(conn)
		if err != nil {
			return nil, err
		}

		u.Auth = libplugin.CreatePrivateKeyAuth(priv, cert)
	default:
		return nil, fmt.Errorf("pipe to does not support any auth method")
	}

	return u, err
>>>>>>> upstream/master:libplugin/skel/skel.go
}

func VerifyHostKeyFromKnownHosts(knownhostsData io.Reader, hostname, netaddr string, key []byte) error {
	hostKeyCallback, err := knownhosts.NewFromReader(knownhostsData)
	if err != nil {
		return err
	}

	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", netaddr)
	if err != nil {
		return err
	}

	return hostKeyCallback(hostname, addr, pub)
}
