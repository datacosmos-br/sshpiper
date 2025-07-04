package plugin

import (
	"fmt"
	"net"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type ChainPlugins struct {
	pluginsCallback []*GrpcPluginConfig
	plugins         []*GrpcPlugin
}

func (cp *ChainPlugins) Append(p *GrpcPlugin) error {
	config, err := p.CreatePiperConfig()
	if err != nil {
		return err
	}

	p.OnNextPlugin = cp.onNextPlugin
	cp.pluginsCallback = append(cp.pluginsCallback, config)
	cp.plugins = append(cp.plugins, p)

	return nil
}

func (cp *ChainPlugins) onNextPlugin(challengeCtx ssh.ChallengeContext, upstream *libplugin.UpstreamNextPluginAuth) error {
	chain := challengeCtx.(*chainConnMeta)

	if upstream.Meta != nil {
		if chain.Metadata == nil {
			chain.Metadata = make(map[string]string)
		}

		for k, v := range upstream.Meta {
			chain.Metadata[k] = v
		}
	}

	if chain.current+1 >= len(cp.pluginsCallback) {
		return fmt.Errorf("no more plugins")
	}

	chain.current++
	return nil
}

type chainConnMeta struct {
	PluginConnMeta
	current int
}

func (cp *ChainPlugins) CreateChallengeContext(conn ssh.ServerPreAuthConn) (ssh.ChallengeContext, error) {
	uiq, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	meta := chainConnMeta{
		PluginConnMeta: PluginConnMeta{
			UserName: conn.User(),
			FromAddr: conn.RemoteAddr().String(),
			UniqId:   uiq.String(),
			Metadata: make(map[string]string),
		},
	}

	for _, p := range cp.plugins {
		if err := p.NewConnection(&meta.PluginConnMeta); err != nil {
			return nil, err
		}
	}

	return &meta, nil
}

func (cp *ChainPlugins) NextAuthMethods(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
	chain := challengeCtx.(*chainConnMeta)
	config := cp.pluginsCallback[chain.current]

	if config.NextAuthMethods != nil {
		return config.NextAuthMethods(conn, challengeCtx)
	}

	var methods []string

	if config.NoClientAuthCallback != nil {
		methods = append(methods, "none")
	}

	if config.PasswordCallback != nil {
		methods = append(methods, "password")
	}

	if config.PublicKeyCallback != nil {
		methods = append(methods, "publickey")
	}

	if config.KeyboardInteractiveCallback != nil {
		methods = append(methods, "keyboard-interactive")
	}

	log.Debugf("next auth methods %v", methods)
	return methods, nil
}

func (cp *ChainPlugins) InstallPiperConfig(config *GrpcPluginConfig) error {

	config.CreateChallengeContext = func(downconn ssh.ServerPreAuthConn) (ssh.ChallengeContext, error) {
		ctx, err := cp.CreateChallengeContext(downconn)
		if err != nil {
			log.Errorf("cannot create challenge context %v", err)
		}
		return ctx, err
	}

	config.NextAuthMethods = cp.NextAuthMethods

	config.NoClientAuthCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].NoClientAuthCallback(conn, challengeCtx)
	}

	config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].PasswordCallback(conn, password, challengeCtx)
	}

	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].PublicKeyCallback(conn, key, challengeCtx)
	}

	config.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].KeyboardInteractiveCallback(conn, client, challengeCtx)
	}

	config.UpstreamAuthFailureCallback = func(conn ssh.ConnMetadata, method string, err error, challengeCtx ssh.ChallengeContext) {
		for _, p := range cp.pluginsCallback {
			if p.UpstreamAuthFailureCallback != nil {
				p.UpstreamAuthFailureCallback(conn, method, err, challengeCtx)
			}
		}
	}

	config.DownstreamBannerCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) string {
		cur := cp.pluginsCallback[challengeCtx.(*chainConnMeta).current]
		if cur.DownstreamBannerCallback != nil {
			return cur.DownstreamBannerCallback(conn, challengeCtx)
		}

		return ""
	}

	config.PipeStartCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) {
		for _, p := range cp.pluginsCallback {
			if p.PipeStartCallback != nil {
				p.PipeStartCallback(conn, challengeCtx)
			}
		}
	}

	config.PipeErrorCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext, err error) {
		for _, p := range cp.pluginsCallback {
			if p.PipeErrorCallback != nil {
				p.PipeErrorCallback(conn, challengeCtx, err)
			}
		}
	}

	config.PipeCreateErrorCallback = func(conn net.Conn, err error) {
		for _, p := range cp.pluginsCallback {
			if p.PipeCreateErrorCallback != nil {
				p.PipeCreateErrorCallback(conn, err)
			}
		}
	}

	return nil
}
