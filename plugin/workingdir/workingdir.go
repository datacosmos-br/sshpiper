package main

import (
	"bufio"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
)

type workingdir struct {
	Path        string
	NoCheckPerm bool
	Strict      bool
}

var (
	// Base username validation on Debians default: https://sources.debian.net/src/adduser/3.113%2Bnmu3/adduser.conf/#L85
	// -> NAME_REGEX="^[a-z][-a-z0-9_]*\$"
	// The length is limited to 32 characters. See man 8 useradd: https://linux.die.net/man/8/useradd
	usernameRule *regexp.Regexp = regexp.MustCompile("^[a-z_][-a-z0-9_]{0,31}$")
)

const (
	userAuthorizedKeysFile = "authorized_keys"
	userKeyFile            = "id_rsa"
	userUpstreamFile       = "sshpiper_upstream"
	userKnownHosts         = "known_hosts"
)

func isUsernameSecure(user string) bool {
	return usernameRule.MatchString(user)
}

func (w *workingdir) fullpath(file string) string {
	return path.Join(w.Path, file)
}

func (w *workingdir) Readfile(file string) ([]byte, error) {
	if !w.NoCheckPerm {
		if err := libplugin.CheckFilePerm(w.fullpath(file)); err != nil {
			return nil, err
		}
	}

	return os.ReadFile(w.fullpath(file))
}

func (w *workingdir) Exists(file string) bool {
	info, err := os.Stat(w.fullpath(file))
	if os.IsNotExist(err) {
		return false
	}

	return !info.IsDir()
}

// TODO refactor this
func parseUpstreamFile(data string) (host string, user string, err error) {
	r := bufio.NewReader(strings.NewReader(data))
	for {
		host, err = r.ReadString('\n')
		if err != nil {
			break
		}

		host = strings.TrimSpace(host)

		if host != "" && host[0] != '#' {
			break
		}
	}

	t := strings.SplitN(host, "@", 2)

	if len(t) > 1 {
		user = t[0]
		host = t[1]
	}

	_, _, err = libplugin.SplitHostPortForSSH(host)

	return
}
