// Package libplugin provides CLI utility helpers for plugin command-line interfaces.
//
// This file contains:
//   - StringMapFlag: A urfave/cli compatible flag for parsing comma-separated key=value pairs into a map[string]string
//
// This helper is used by plugins to easily accept and parse map-style CLI flags.
//
// Example usage:
//
//	--env FOO=bar,BAR=baz
package libplugin

import (
	"fmt"
	"strings"
)

// KeyValueMapFlag is a urfave/cli compatible flag for key=value pairs.
// It parses comma-separated key=value pairs into a map[string]string.
//
// Example usage:
//
//	--env FOO=bar,BAR=baz
//
// Supports empty values (e.g., --env FOO=,BAR=baz) and ignores empty items.
type KeyValueMapFlag struct {
	// Value holds the parsed key-value pairs.
	Value map[string]string
}

// Parse parses a comma-separated list of key=value pairs into the Value map.
// Returns an error if any item is not in key=value format.
// Ignores empty items and supports empty values.
// Example usage:
//
//	var f KeyValueMapFlag
//	err := f.Parse("FOO=bar,BAR=baz")
func (f *KeyValueMapFlag) Parse(value string) error {
	if f.Value == nil {
		f.Value = make(map[string]string)
	}
	if value == "" {
		return nil
	}
	allItems := strings.Split(value, ",")
	for _, item := range allItems {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid format for item '%s', expecting key=value", item)
		}
		key := strings.TrimSpace(parts[0])
		val := parts[1] // allow empty value
		if key == "" {
			return fmt.Errorf("empty key in item '%s'", item)
		}
		f.Value[key] = val
	}
	return nil
}

// Format returns the flag value as a comma-separated key=value list.
// Keys and values are not escaped; use with care if values may contain commas or equals.
// Example usage:
//
//	s := f.Format()
func (f *KeyValueMapFlag) Format() string {
	if len(f.Value) == 0 {
		return ""
	}
	var result []string
	for k, v := range f.Value {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(result, ",")
}
