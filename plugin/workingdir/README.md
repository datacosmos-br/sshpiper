# Workingdir Plugin

The Workingdir plugin provides SSH access based on directory structures and file-based configuration.

## Features

- **Standardized Authentication**: Uses `libplugin.StandardTestPassword` for consistent htpasswd-based authentication
- **Standardized Key Management**: Uses `libplugin.StandardAuthorizedKeys` and `libplugin.StandardTrustedUserCAKeys` for SSH key handling  
- **Standardized Connection Security**: Uses `libplugin.StandardKnownHosts` and `libplugin.StandardIgnoreHostKey` for host verification
- **Standardized Private Keys**: Uses `libplugin.StandardPrivateKey` for upstream authentication
- **Directory-based Configuration**: File-based configuration with working directory isolation
- **Environment Variable Expansion**: Automatic expansion of `${DOWNSTREAM_USER}` in file paths

## Implementation

The plugin uses the standardized `libplugin.Standard*` helpers for all common operations, ensuring consistency across all SSHPiper plugins and eliminating code duplication. All file operations include proper environment variable expansion and base directory resolution.

## Authentication Methods

- **Password Authentication**: htpasswd file-based using `StandardTestPassword`
- **Public Key Authentication**: authorized_keys file-based using `StandardAuthorizedKeys`
- **Certificate Authentication**: CA keys file-based using `StandardTrustedUserCAKeys`

## Configuration Files

All configuration files support:

- Automatic environment variable expansion
- Relative path resolution based on working directory
- Existence checks before processing
- Consistent error handling and logging

The plugin maintains workingdir-specific behavior while using standardized helpers for all common operations.

# Working Directory plugin for sshpiperd

`Working Dir` is a `/home`-like directory.
sshpiperd read files from `workingdir/[username]/` to know upstream's configuration.

e.g.

```ascii
workingdir tree

.
├── github
│   └── sshpiper_upstream
└── linode
    └── sshpiper_upstream
```

when `ssh sshpiper_host -l github`,
sshpiper reads `workingdir/github/sshpiper_upstream` and the connect to the upstream.

## Usage

```bash
sshpiperd workingdir --root /var/sshpiper
```

### options (allow supported read from environments)

```bash
--allow-baduser-name  allow bad username (default: false) [$SSHPIPERD_WORKINGDIR_ALLOWBADUSERNAME]
--no-check-perm       disable 0400 checking (default: false) [$SSHPIPERD_WORKINGDIR_NOCHECKPERM]
--no-password-auth    disable password authentication and only use public key authentication (default: false) [$SSHPIPERD_WORKINGDIR_NOPASSWORD_AUTH]
--root value          path to root working directory (default: "/var/sshpiper") [$SSHPIPERD_WORKINGDIR_ROOT]
--strict-hostkey      upstream host public key must be in known_hosts file, otherwise drop the connection (default: false) [$SSHPIPERD_WORKINGDIR_STRICTHOSTKEY]
```

## User files

*These file MUST NOT be accessible to group or other. (chmod og-rwx filename)*

- sshpiper_upstream

  - line starts with `#` are treated as comment
  - only the first not comment line will be parsed
  - if no port was given, 22 will be used as default
  - if `user@` was defined, username to upstream will be the mapped one

```bash
# comment
[user@]upstream[:22]
```

```bash
e.g. 

git@github.com

google.com:12345

```

- authorized_keys
  
   OpenSSH format `authorized_keys` (see `~/.ssh/authorized_keys`). `downstream`'s public key must be in this file to get verified in order to use `id_rsa` to login to `upstream`.

- id_rsa

   RSA key for upstream.

- known_hosts

   when `--strict-hostkey` is set, upstream server's public key must present in known_hosts

## Recursive mode (--recursive-search)

`--recursive-search` will search all sub directories of the `username` directory to find the `downstream` key in `authorized_keys` file.

```bash
├── git
│   ├── bitbucket
│   │   └── sshpiper_upstream
│   ├── github
│   │   ├── authorized_keys
│   │   ├── id_rsa
│   │   └── sshpiper_upstream
│   └── gitlab
│       └── sshpiper_upstream
├── linode....
```

## TOTP

`--check-totp` will check the TOTP 2FA before connecting to the upstream, compatible with all [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238) authenticator, for example: `google authenticator`, `azure authenticator`.

the secret should be stored in `totp` file in working directory.
for example:

```bash
/var/sshpiper/username/totp
```

## FAQ

- Q: Why sshpiperd still asks for password even I disabled password auth in upstream (different behavior from `v0`)
   A: You may want `--no-password-auth`, see <https://github.com/tg123/sshpiper/issues/97>
- Q: What if I want to use a different key type for the SSH server instead of RSA?
   A: The [`workingdir` plugin hard-codes for `id_rsa` for simplicity](https://github.com/tg123/sshpiper/issues/554#issue-2959158335). Consider a different plugin like `yaml` if you need more flexibility.
