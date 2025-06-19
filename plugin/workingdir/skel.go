package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
)

type workdingdirFactory struct {
	root             string
	allowBadUsername bool
	noPasswordAuth   bool
	noCheckPerm      bool
	strictHostKey    bool
	recursiveSearch  bool
}

type skelpipeWrapper struct {
	libplugin.SkelPipeWrapper
	dir      *workingdir
	host     string
	username string
}

type skelpipeFromWrapper struct {
	skelpipeWrapper
}

type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	skelpipeWrapper
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeWrapper) From() []skel.SkelPipeFrom {
	w := skelpipeFromWrapper{
		skelpipeWrapper: *s,
	}

	if s.dir.Exists(userAuthorizedKeysFile) && s.dir.Exists(userKeyFile) {
		return []skel.SkelPipeFrom{&skelpipePublicKeyWrapper{
			skelpipeFromWrapper: w,
		}}
	} else {
		return []skel.SkelPipeFrom{&skelpipePasswordWrapper{
			skelpipeFromWrapper: w,
		}}
	}
}

func (s *skelpipeWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.host
}

func (s *skelpipeWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	// Use standard helper for host key ignoring logic
	knownHostsFile := ""
	if s.dir.Exists(userKnownHosts) {
		knownHostsFile = s.dir.fullpath(userKnownHosts)
	}
	return libplugin.StandardIgnoreHostKey(!s.dir.Strict, "", knownHostsFile)
}

func (s *skelpipeWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	// Use standard helper for known hosts loading
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	knownHostsFile := s.dir.fullpath(userKnownHosts)
	return libplugin.StandardKnownHosts("", knownHostsFile, envVars, s.dir.Path)
}

// TestPassword delegates to libplugin.StandardTestPassword for password authentication.
func (s *skelpipeWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	// Check if password file exists
	if !s.dir.Exists(userPasswordFile) {
		// If no password file exists, allow connection (workingdir default behavior)
		log.Debugf("no password file found for user %s, allowing connection", conn.User())
		return true, nil
	}

	// Use standard helper with the workingdir password file
	passwordFile := s.dir.fullpath(userPasswordFile)
	return libplugin.StandardTestPassword("", passwordFile, conn.User(), password)
}

// AuthorizedKeys loads authorized keys using libplugin.StandardAuthorizedKeys.
func (s *skelpipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	// Use standard libplugin helper for authorized keys loading
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	keysFile := s.dir.fullpath(userAuthorizedKeysFile)
	return libplugin.StandardAuthorizedKeys("", keysFile, envVars, s.dir.Path)
}

// TrustedUserCAKeys loads trusted CA keys using libplugin.StandardTrustedUserCAKeys.
func (s *skelpipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	// Check if file exists first (workingdir behavior)
	if !s.dir.Exists(userTrustedUserCAKeysFile) {
		return nil, nil
	}

	// Use standard libplugin helper for trusted CA keys loading
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	caKeysFile := s.dir.fullpath(userTrustedUserCAKeysFile)
	return libplugin.StandardTrustedUserCAKeys("", caKeysFile, envVars, s.dir.Path)
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
	if s.dir.Exists(userKeyFile) {
		return &skelpipeToPrivateKeyWrapper{
			skelpipeToWrapper: skelpipeToWrapper(*s),
		}, nil
	}

	return &skelpipeToPasswordWrapper{
		skelpipeToWrapper: skelpipeToWrapper(*s),
	}, nil
}

func (wf *workdingdirFactory) listPipe(conn libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	user := conn.User()

	if !wf.allowBadUsername {
		if !isUsernameSecure(user) {
			return nil, fmt.Errorf("bad username: %s", user)
		}
	}

	var pipes []skel.SkelPipe
	userdir := path.Join(wf.root, conn.User())

	_ = filepath.Walk(userdir, func(path string, info os.FileInfo, err error) (stop error) {
		log.Infof("search upstreams in path: %v", path)
		if err != nil {
			log.Infof("error walking path: %v", err)
			return
		}

		if !info.IsDir() {
			return
		}

		if !wf.recursiveSearch {
			stop = fmt.Errorf("stop")
		}

		w := &workingdir{
			Path:        path,
			NoCheckPerm: wf.noCheckPerm,
			Strict:      wf.strictHostKey,
		}

		data, err := w.Readfile(userUpstreamFile)
		if err != nil {
			log.Infof("error reading upstream file: %v in %v", err, w.Path)
			return
		}

		host, user, err := parseUpstreamFile(string(data))
		if err != nil {
			log.Infof("ignore upstream folder %v due to: %v", w.Path, err)
			return
		}

		pipes = append(pipes, &skelpipeWrapper{
			dir:      w,
			host:     host,
			username: user,
		})

		return
	})

	return pipes, nil
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	// Use standard helper for private key loading
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	keyFile := s.dir.fullpath(userKeyFile)
	return libplugin.StandardPrivateKey("", keyFile, envVars, s.dir.Path)
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	// Use standard helper for override password loading
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardOverridePassword("", "", envVars, s.dir.Path)
}
