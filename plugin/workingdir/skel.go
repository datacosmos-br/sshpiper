package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
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
	dir      *workingdir
	host     string
	username string
}

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {
	fromSpecs := []interface{}{s}
	matchConnFn := func(from interface{}, conn libplugin.PluginConnMetadata) (libplugin.SkelPipeTo, error) {
		w := from.(*skelpipeWrapper)
		var to libplugin.SkelPipeToWrapper
		if w.dir.Exists(userKeyFile) {
			knownHostsFn := func(conn libplugin.PluginConnMetadata) ([]byte, error) {
				return w.dir.Readfile(userKnownHosts)
			}
			to = libplugin.NewSkelPipeToWrapper(w.dir, nil, w.username, w.host, !w.dir.Strict, knownHostsFn)
			return &to, nil
		}
		to = libplugin.NewSkelPipeToWrapper(w.dir, nil, w.username, w.host, !w.dir.Strict, nil)
		return &to, nil
	}
	return libplugin.FromGeneric(s.dir, s, fromSpecs, matchConnFn, nil)
}

func (s *skelpipeWrapper) User(conn libplugin.PluginConnMetadata) string {
	return s.username
}

func (s *skelpipeWrapper) Host(conn libplugin.PluginConnMetadata) string {
	return s.host
}

func (s *skelpipeWrapper) IgnoreHostKey(conn libplugin.PluginConnMetadata) bool {
	return !s.dir.Strict
}

func (s *skelpipeWrapper) KnownHosts(conn libplugin.PluginConnMetadata) ([]byte, error) {
	return s.dir.Readfile(userKnownHosts)
}

func (wf *workdingdirFactory) listPipe(conn libplugin.PluginConnMetadata) ([]libplugin.SkelPipe, error) {
	user := conn.User()

	if !wf.allowBadUsername {
		if !isUsernameSecure(user) {
			return nil, fmt.Errorf("bad username: %s", user)
		}
	}

	var pipes []libplugin.SkelPipe
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
