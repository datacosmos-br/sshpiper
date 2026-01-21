package main

import (
	"bufio"
	"fmt"
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

// Base username validation on Debians default: https://sources.debian.net/src/adduser/3.113%2Bnmu3/adduser.conf/#L85
// -> NAME_REGEX="^[a-z][-a-z0-9_]*\$"
// The length is limited to 32 characters. See man 8 useradd: https://linux.die.net/man/8/useradd
var usernameRule = regexp.MustCompile("^[a-z_][-a-z0-9_]{0,31}$")

const (
	userAuthorizedKeysFile    = "authorized_keys"
	userKeyFile               = "id_rsa"
	userUpstreamFile          = "sshpiper_upstream"
	userKnownHosts            = "known_hosts"
	userPasswordFile          = "password"
	userTrustedUserCAKeysFile = "trusted_user_ca_keys"
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

// parseUpstreamFile parses the upstream file content and extracts host and user information.
// Format supports: "host:port" or "user@host:port" with comments starting with #
func parseUpstreamFile(data string) (host, user string, err error) {
	if data == "" {
		return "", "", fmt.Errorf("upstream file data is empty")
	}

	scanner := bufio.NewScanner(strings.NewReader(data))
	var validLine string

	// Find first non-comment, non-empty line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			validLine = line
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("error reading upstream file: %w", err)
	}

	if validLine == "" {
		return "", "", fmt.Errorf("no valid upstream configuration found")
	}

	// Parse user@host format
	parts := strings.SplitN(validLine, "@", 2)
	if len(parts) == 2 {
		user = strings.TrimSpace(parts[0])
		host = strings.TrimSpace(parts[1])
	} else {
		host = strings.TrimSpace(validLine)
	}

	// Validate host format
	if host == "" {
		return "", "", fmt.Errorf("host cannot be empty")
	}

	// Validate host:port format using libplugin helper
	_, _, err = libplugin.SplitHostPortForSSH(host)
	if err != nil {
		return "", "", fmt.Errorf("invalid host:port format '%s': %w", host, err)
	}

	return host, user, nil
}
