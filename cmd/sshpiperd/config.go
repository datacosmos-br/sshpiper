// Package sshpiperd provides the main SSH proxy daemon implementation.
// This file contains the professional-grade configuration system with
// comprehensive validation, structured logging, and modern Go patterns.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

// ConfigError represents configuration-related errors with structured context
type ConfigError struct {
	Field   string
	Value   interface{}
	Reason  string
	Context map[string]interface{}
}

func (e ConfigError) Error() string {
	return fmt.Sprintf("configuration error in field '%s': %s (value: %v)", e.Field, e.Reason, e.Value)
}

// LogLevel represents available logging levels with validation
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
	LogLevelPanic LogLevel = "panic"
)

// IsValid validates if the log level is supported
func (l LogLevel) IsValid() bool {
	switch l {
	case LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, LogLevelFatal, LogLevelPanic:
		return true
	default:
		return false
	}
}

// ToSlogLevel converts to slog.Level for structured logging
func (l LogLevel) ToSlogLevel() slog.Level {
	switch l {
	case LogLevelTrace:
		return slog.LevelDebug - 4
	case LogLevelDebug:
		return slog.LevelDebug
	case LogLevelInfo:
		return slog.LevelInfo
	case LogLevelWarn:
		return slog.LevelWarn
	case LogLevelError:
		return slog.LevelError
	case LogLevelFatal, LogLevelPanic:
		return slog.LevelError + 4
	default:
		return slog.LevelInfo
	}
}

// Config represents the complete SSHPiper daemon configuration
type Config struct {
	Address        string        `json:"address"`
	Port           int           `json:"port"`
	ServerKey      string        `json:"server_key"`
	LogLevel       LogLevel      `json:"log_level"`
	LogFormat      string        `json:"log_format"`
	LoginGraceTime time.Duration `json:"login_grace_time"`
}

// NewConfigFromContext creates a new Config from CLI context with validation
func NewConfigFromContext(ctx *cli.Context) (*Config, error) {
	config := &Config{
		Address:        ctx.String("address"),
		Port:           ctx.Int("port"),
		ServerKey:      ctx.String("server-key"),
		LogLevel:       LogLevel(ctx.String("log-level")),
		LogFormat:      ctx.String("log-format"),
		LoginGraceTime: ctx.Duration("login-grace-time"),
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// Validate performs comprehensive validation of the configuration
func (c *Config) Validate() error {
	var validationErrors []error

	if c.Port < 1 || c.Port > 65535 {
		validationErrors = append(validationErrors, ConfigError{
			Field:  "port",
			Value:  c.Port,
			Reason: "port must be between 1 and 65535",
		})
	}

	if !c.LogLevel.IsValid() {
		validationErrors = append(validationErrors, ConfigError{
			Field:  "log_level",
			Value:  c.LogLevel,
			Reason: "invalid log level",
		})
	}

	if len(validationErrors) > 0 {
		return errors.Join(validationErrors...)
	}

	return nil
}

// SetupLogger configures structured logging
func (c *Config) SetupLogger() *slog.Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: c.LogLevel.ToSlogLevel(),
	}

	if c.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}
