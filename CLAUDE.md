# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SSHPiper is a reverse proxy for SSH that routes connections from downstream clients to upstream servers based on configurable rules. It supports all SSH protocols including ssh, scp, and port forwarding.

**Stack**: Go 1.24+, gRPC, Docker, Kubernetes CRDs, YAML configs

### Terminology
- **downstream**: Client side (SSH client connecting to sshpiper)
- **upstream**: Server side (SSH server that sshpiper connects to)
- **plugin**: Handles routing decisions and authentication mapping between downstream and upstream
- **additional challenge**: Extra authentication steps a plugin can require (e.g., 2FA)

## Build Commands

```bash
# Build all (main + plugins)
make build

# Quick development cycle
make dev              # fmt + build + test
make dev-quick        # fmt + build only

# Run tests
make test             # Unit tests with coverage
make test-race        # Race condition detection
make e2e              # Full E2E suite
make e2e-quick        # Smoke tests only

# Quality checks
make quality          # Full quality gate validation
make lint             # Linting only

# Clean
make clean
```

### Manual Build

```bash
git submodule update --init --recursive
mkdir -p bin
go build -tags full -o bin ./...
```

### Running

```bash
# Start sshpiperd with fixed plugin
./bin/sshpiperd -i /tmp/sshpiperkey --server-key-generate-mode notexist \
    --log-level=trace ./bin/fixed --target 127.0.0.1:5522

# Chain plugins (separated by --)
./bin/sshpiperd -i /tmp/key ./bin/simplemath -- ./bin/fixed --target 127.0.0.1:5522
```

## Architecture

```
cmd/sshpiperd/          # Main daemon binary
├── daemon.go           # Core SSH proxy logic, connection handling
├── main.go             # CLI setup, plugin loading
├── grpc.go             # gRPC plugin communication
└── internal/plugin/    # Plugin interface internals

libplugin/              # Plugin development framework
├── pluginbase.go       # Base plugin interfaces
├── skelhelpers.go      # Standard authentication helpers
├── standard_*.go       # Standardized plugin factories
├── plugin.proto        # gRPC protocol definition
└── ioconn/             # stdin/stdout to net.Conn wrapper

plugin/                 # Individual plugins
├── fixed/              # Simple fixed-target routing
├── yaml/               # YAML config file routing
├── workingdir/         # /home-like directory routing
├── docker/             # Docker container routing
├── kubernetes/         # Kubernetes CRD routing
├── failtoban/          # IP ban after failed attempts
├── simplemath/         # Demo additional challenge
└── username-router/    # Route by username pattern

crypto/                 # Forked golang.org/x/crypto with SSH piper extensions
                        # Key file: crypto/ssh/sshpiper.go
```

### Plugin Communication

Plugins are separate processes communicating with sshpiperd via gRPC. Most plugins use stdin/stdout wrapped as net.Conn (`libplugin/ioconn`). Remote gRPC connections are also supported.

### Key Interfaces

```go
// Plugin routing callback - return upstream connection details
type PluginConfig struct {
    PasswordCallback func(conn ConnMetadata, password []byte) (*Upstream, error)
    PublicKeyCallback func(conn ConnMetadata, key ssh.PublicKey) (*Upstream, error)
    // ...
}

// Upstream connection target
type Upstream struct {
    Host          string
    Port          int32
    UserName      string      // Override downstream username
    IgnoreHostKey bool
    Auth          isUpstream_Auth  // Password, PublicKey, or None
}
```

## Creating a Plugin

Minimal plugin example (see `plugin/fixed/main.go`):

```go
package main

import (
    "github.com/tg123/sshpiper/libplugin"
    "github.com/urfave/cli/v2"
)

func main() {
    libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
        Name:  "myplugin",
        Usage: "My plugin description",
        Flags: []cli.Flag{
            &cli.StringFlag{Name: "target", Required: true},
        },
        CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) {
            host, port, _ := libplugin.SplitHostPortForSSH(c.String("target"))
            return &libplugin.PluginConfig{
                PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
                    return &libplugin.Upstream{
                        Host: host, Port: int32(port),
                        IgnoreHostKey: true,
                        Auth: libplugin.CreatePasswordAuth(password),
                    }, nil
                },
            }, nil
        },
    })
}
```

### Standard Helpers (libplugin)

Use these for common operations:
- `StandardTestPassword()` - htpasswd authentication
- `StandardAuthorizedKeys()` - SSH key loading (file/data/base64)
- `StandardKnownHosts()` - Host key verification
- `StandardPrivateKey()` - Private key loading
- `SplitHostPortForSSH()` - Parse host:port with SSH default

## Code Quality Standards

### Required Before Commits

- All tests must pass: `go test ./...`
- Zero compilation warnings
- No `panic()` in production code paths (use error returns)
- No mock/fake code in production (tests only)

### Patterns to Follow

- Use `libplugin` helpers for standard operations
- Wrap errors with context: `fmt.Errorf("operation failed: %w", err)`
- Graceful error handling (no process-killing panics)
- Consistent plugin patterns across implementations

## Testing

### E2E Development Environment

```bash
cd e2e
SSHPIPERD_DEBUG=1 docker-compose up --force-recreate --build -d

# Test servers available:
# - host-password:2222 (user: user, password: pass)
# - host-publickey:2222 (add key to /publickey_authorized_keys/authorized_keys)
```

### Running Specific Tests

```bash
go test ./plugin/yaml/...           # Test specific plugin
go test -v -run TestName ./...      # Run specific test
go test -race ./...                 # Race detection
```

## Key Files

- `crypto/ssh/sshpiper.go` - Core SSH proxy API extensions
- `cmd/sshpiperd/daemon.go` - Main proxy loop and connection handling
- `libplugin/pluginbase.go` - Plugin interfaces
- `libplugin/skelhelpers.go` - Standard authentication helpers
