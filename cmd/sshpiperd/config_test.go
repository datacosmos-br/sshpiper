package main

import (
	"testing"
	"time"

	"github.com/urfave/cli/v2"
)

// BenchmarkConfigValidation benchmarks the configuration validation process
func BenchmarkConfigValidation(b *testing.B) {
	// Create a mock CLI context with typical values
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "address", Value: "0.0.0.0"},
			&cli.IntFlag{Name: "port", Value: 2222},
			&cli.StringFlag{Name: "server-key", Value: "/etc/ssh/ssh_host_ed25519_key"},
			&cli.StringFlag{Name: "log-level", Value: "info"},
			&cli.StringFlag{Name: "log-format", Value: "json"},
			&cli.DurationFlag{Name: "login-grace-time", Value: 30 * time.Second},
		},
	}

	ctx := cli.NewContext(app, nil, nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		config, err := NewConfigFromContext(ctx)
		if err != nil {
			b.Fatal(err)
		}
		_ = config
	}
}

// BenchmarkLogLevelValidation benchmarks log level validation
func BenchmarkLogLevelValidation(b *testing.B) {
	levels := []LogLevel{
		LogLevelTrace, LogLevelDebug, LogLevelInfo,
		LogLevelWarn, LogLevelError, LogLevelFatal, LogLevelPanic,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		level := levels[i%len(levels)]
		_ = level.IsValid()
		_ = level.ToSlogLevel()
	}
}

// BenchmarkConfigCreation benchmarks configuration object creation
func BenchmarkConfigCreation(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		config := &Config{
			Address:        "127.0.0.1",
			Port:           2222,
			ServerKey:      "/etc/ssh/key",
			LogLevel:       LogLevelInfo,
			LogFormat:      "json",
			LoginGraceTime: 30 * time.Second,
		}

		err := config.Validate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestLogLevelValidation tests log level validation
func TestLogLevelValidation(t *testing.T) {
	validLevels := []LogLevel{
		LogLevelTrace, LogLevelDebug, LogLevelInfo,
		LogLevelWarn, LogLevelError, LogLevelFatal, LogLevelPanic,
	}

	for _, level := range validLevels {
		if !level.IsValid() {
			t.Errorf("Expected %s to be valid", level)
		}
	}

	invalidLevel := LogLevel("invalid")
	if invalidLevel.IsValid() {
		t.Error("Expected 'invalid' to be invalid")
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Address:        "127.0.0.1",
				Port:           2222,
				LogLevel:       LogLevelInfo,
				LoginGraceTime: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "invalid port",
			config: Config{
				Address:        "127.0.0.1",
				Port:           0,
				LogLevel:       LogLevelInfo,
				LoginGraceTime: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			config: Config{
				Address:        "127.0.0.1",
				Port:           2222,
				LogLevel:       LogLevel("invalid"),
				LoginGraceTime: 30 * time.Second,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
