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

import (
	"bytes"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"

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
	listPipe func(PluginConnMetadata) ([]SkelPipe, error)
}

// NewSkelPlugin creates a new SkelPlugin with the given listPipe function.
//
// Example usage:
//
//	skel := NewSkelPlugin(listPipeFn)
func NewSkelPlugin(listPipe func(PluginConnMetadata) ([]SkelPipe, error)) *SkelPlugin {
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
	MatchConn(conn PluginConnMetadata) (SkelPipeTo, error)
}

// SkelPipeFromPassword is a SkelPipeFrom that supports password authentication.
//
// Example usage:
//
//	ok, err := from.TestPassword(conn, password)
type SkelPipeFromPassword interface {
	SkelPipeFrom
	TestPassword(conn PluginConnMetadata, password []byte) (bool, error)
}

// SkelPipeFromPublicKey is a SkelPipeFrom that supports public key authentication.
//
// Example usage:
//
//	keys, err := from.AuthorizedKeys(conn)
type SkelPipeFromPublicKey interface {
	SkelPipeFrom
	AuthorizedKeys(conn PluginConnMetadata) ([]byte, error)
	TrustedUserCAKeys(conn PluginConnMetadata) ([]byte, error)
}

// SkelPipeTo represents an upstream connection target.
//
// Example usage:
//
//	host := to.Host(conn)
type SkelPipeTo interface {
	Host(conn PluginConnMetadata) string
	User(conn PluginConnMetadata) string
	IgnoreHostKey(conn PluginConnMetadata) bool
	KnownHosts(conn PluginConnMetadata) ([]byte, error)
}

// SkelPipeToPassword is a SkelPipeTo that supports password override.
//
// Example usage:
//
//	pass, err := to.OverridePassword(conn)
type SkelPipeToPassword interface {
	SkelPipeTo
	OverridePassword(conn PluginConnMetadata) ([]byte, error)
}

// SkelPipeToPrivateKey is a SkelPipeTo that supports private key authentication.
//
// Example usage:
//
//	priv, cert, err := to.PrivateKey(conn)
type SkelPipeToPrivateKey interface {
	SkelPipeTo
	PrivateKey(conn PluginConnMetadata) ([]byte, []byte, error)
}

// CreateConfig returns a PluginConfig with SkelPlugin's callbacks.
//
// Example usage:
//
//	config := skel.CreateConfig()
func (p *SkelPlugin) CreateConfig() *PluginConfig {
	return &PluginConfig{
		NextAuthMethodsCallback: p.SupportedMethods,
		PasswordCallback:        p.PasswordCallback,
		PublicKeyCallback:       p.PublicKeyCallback,
		VerifyHostKeyCallback:   p.VerifyHostKeyCallback,
	}
}

// SupportedMethods returns the supported authentication methods for a connection.
//
// Example usage:
//
//	methods, err := skel.SupportedMethods(conn)
func (p *SkelPlugin) SupportedMethods(conn PluginConnMetadata) ([]string, error) {
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

// VerifyHostKeyCallback verifies the upstream host key using the cached SkelPipeTo.
//
// Example usage:
//
//	err := skel.VerifyHostKeyCallback(conn, hostname, netaddr, key)
func (p *SkelPlugin) VerifyHostKeyCallback(conn PluginConnMetadata, hostname, netaddr string, key []byte) error {
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

// match finds a matching SkelPipeFrom and SkelPipeTo for the connection, using the provided verify function.
//
// Example usage:
//
//	from, to, err := skel.match(conn, verifyFn)
func (p *SkelPlugin) match(conn PluginConnMetadata, verify func(SkelPipeFrom) (bool, error)) (SkelPipeFrom, SkelPipeTo, error) {
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
}
