//go:build ignore

package main

import (
	"encoding/base64"

	"github.com/tg123/sshpiper/libplugin"
)

type pipe struct {
	ClientUsername    string
	ContainerUsername string
	Host              string
	AuthorizedKeys    string
	PrivateKey        string
}

type plugin struct {
	dockerCli interface{} // placeholder, not used in skel.go
}

type skelpipeWrapper struct {
	plugin *plugin

	pipe   *pipe
}

type skelpipeFromWrapper struct {
	skelpipeWrapper
}

type skelpipeFromPasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipeFromPublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	skelpipeWrapper

	username string
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {

	w := skelpipeFromWrapper{
		skelpipeWrapper: *s,
	}

	if s.pipe != nil && (s.pipe.PrivateKey != "" || s.pipe.AuthorizedKeys != "") {
		return []libplugin.SkelPipeFrom{&skelpipePublicKeyWrapper{
			skelpipeFromWrapper: w,
		}}
	} else {
		return []libplugin.SkelPipeFrom{&skelpipePasswordWrapper{
			skelpipeFromWrapper: w,
		}}
	}
}

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	if s.pipe != nil {
		return s.pipe.Host
	}
	return ""
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return true // TODO support this
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {
	if s.pipe == nil {
		return nil, nil
	}
	user := conn.User()

	matched := s.pipe.ClientUsername == user || s.pipe.ClientUsername == ""
	targetuser := s.pipe.ContainerUsername

	if targetuser == "" {
		targetuser = user
	}

	if matched {

		if s.pipe.PrivateKey != "" {
			return &skelpipeToPrivateKeyWrapper{
				skelpipeToWrapper: skelpipeToWrapper{
					skelpipeWrapper: s.skelpipeWrapper,
					username:        targetuser,
				},
			}, nil
		}

		return &skelpipeToPasswordWrapper{
			skelpipeToWrapper: skelpipeToWrapper{
				skelpipeWrapper: s.skelpipeWrapper,
				username:        targetuser,
			},
		}, nil
	}

	return nil, nil
}

func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	return true, nil // do not test input password
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	if s.pipe == nil {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s.pipe.AuthorizedKeys)
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	if s.pipe == nil {
		return nil, nil, nil
	}
	k, err := base64.StdEncoding.DecodeString(s.pipe.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return k, nil, nil
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil
}

func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]libplugin.SkelPipe, error) {
	dpipes, err := p.list()
	if err != nil {
		return nil, err
	}

	var pipes []libplugin.SkelPipe
	for _, pipe := range dpipes {
		wrapper := &skelpipeWrapper{
			plugin: p,
			pipe:   &pipe,
		}
		pipes = append(pipes, wrapper)

	}

	return pipes, nil
}
