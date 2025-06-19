// Package libplugin provides utilities for file, base64, YAML, and Vault loading for plugin configuration.
//
// This file contains helpers for:
//   - Loading configuration and secrets from files, base64-encoded strings, and Vault
//   - Expanding variables in file paths
//   - Loading and merging multiple files or base64 sources
//   - Checking file permissions for security
//   - Loading YAML config files into Go structs
//   - Utility types for flexible YAML unmarshalling (ListOrString)
//
// Main types and functions:
//   - ListOrString: Allows YAML fields to be a string or a list of strings
//   - LoadFileOrBase64: Loads data from a file or base64 string
//   - LoadFileOrBase64Many: Loads and joins data from multiple files/base64 sources
//   - CheckFilePerm: Ensures file permissions are secure
//   - LoadYAMLConfigFiles: Loads and unmarshals YAML config files
//   - LoadStringAndFileMany: Loads and decodes multiple base64/raw strings and/or files
//
// These helpers are used by plugins to securely and flexibly load configuration and secrets.
//
// Example usage:
//
//	data, err := LoadFileOrBase64("/etc/secret", "", nil, "")
//	keys, err := LoadFileOrBase64Many(ListOrString{Str: "keyfile"}, ListOrString{}, nil, "")
package libplugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"gopkg.in/yaml.v3"
)

// SplitHostPortForSSH splits an address into host and port, defaulting to port 22 if not specified.
// Returns the host, port, and error if parsing fails.
//
// Example: "example.com" -> ("example.com", 22, nil)
//
//	"example.com:2222" -> ("example.com", 2222, nil)
func SplitHostPortForSSH(addr string) (host string, port int, err error) {
	host = addr
	h, p, err := net.SplitHostPort(host)
	if err == nil {
		host = h
		var parsedPort int64
		parsedPort, err = strconv.ParseInt(p, 10, 32)
		if err != nil {
			return
		}
		port = int(parsedPort)
	} else if host != "" {
		// test valid after concat :22
		if _, _, err = net.SplitHostPort(host + ":22"); err == nil {
			port = 22
		}
	}

	if host == "" {
		err = fmt.Errorf("empty addr")
	}

	return
}

// DialForSSH dials a TCP connection to the given address, defaulting to port 22 if not specified.
// Returns a net.Conn and error if dialing fails.
func DialForSSH(addr string) (net.Conn, error) {

	if _, _, err := net.SplitHostPort(addr); err != nil && addr != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(addr + ":22"); err == nil {
			addr += ":22"
		}
	}

	return net.Dial("tcp", addr)
}

// ListOrString is a helper for YAML fields that can be a string or a list of strings.
type ListOrString struct {
	List []string
	Str  string
}

// UnmarshalYAML implements yaml.Unmarshaler to support both string and []string for ListOrString.
func (l *ListOrString) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try as []string
	var list []string
	if err := unmarshal(&list); err == nil {
		l.List = list
		l.Str = ""
		return nil
	}
	// Try as string
	var single string
	if err := unmarshal(&single); err == nil {
		l.List = nil
		l.Str = single
		return nil
	}
	return fmt.Errorf("ListOrString: value is neither string nor []string")
}

// Any returns true if the ListOrString contains any value.
func (l *ListOrString) Any() bool {
	return len(l.List) > 0 || l.Str != ""
}

// Combine returns all values as a single slice.
func (l *ListOrString) Combine() []string {
	if l.Str != "" {
		return append(l.List, l.Str)
	}
	return l.List
}

// LoadFileOrBase64 loads data from a file (with variable expansion and relative to baseDir) or from a base64-encoded string.
// If both file and base64data are empty, returns nil, nil.
// If file is not empty, expands variables using vars, resolves relative to baseDir, and loads the file.
// If base64data is not empty, decodes the base64 string.
// Returns an error if loading or decoding fails.
func LoadFileOrBase64(file string, base64data string, vars map[string]string, baseDir string) ([]byte, error) {
	if file != "" {
		file = os.Expand(file, func(placeholderName string) string {
			if v, ok := vars[placeholderName]; ok {
				return v
			}
			return os.Getenv(placeholderName)
		})
		if !filepath.IsAbs(file) && baseDir != "" {
			file = filepath.Join(baseDir, file)
		}
		return os.ReadFile(file)
	}
	if base64data != "" {
		return base64.StdEncoding.DecodeString(base64data)
	}
	return nil, nil
}

// LoadFileOrBase64Many loads and joins data from multiple files and/or base64-encoded strings.
// Each file path is expanded and resolved relative to baseDir. All data is joined with a newline separator.
// Returns an error if any file or base64 decoding fails.
func LoadFileOrBase64Many(files ListOrString, base64data ListOrString, vars map[string]string, baseDir string) ([]byte, error) {
	var byteSlices [][]byte
	for _, file := range files.Combine() {
		data, err := LoadFileOrBase64(file, "", vars, baseDir)
		if err != nil {
			return nil, err
		}
		if data != nil {
			byteSlices = append(byteSlices, data)
		}
	}
	for _, data := range base64data.Combine() {
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, err
		}
		if decoded != nil {
			byteSlices = append(byteSlices, decoded)
		}
	}
	return bytes.Join(byteSlices, []byte("\n")), nil
}

// CheckFilePerm checks that the file at filename has permissions 0400 (no group/other read/write/exec).
// Returns an error if permissions are too open.
func CheckFilePerm(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			fmt.Printf("error closing file: %v\n", err)
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%v's perm is too open", filename)
	}
	return nil
}

// LoadYAMLConfigFiles loads YAML config files from the given globs, checks permissions (unless noCheckPerm is true),
// and unmarshals each file into the provided slice pointer (must be a pointer to a slice of struct).
// Returns the number of files loaded, or an error.
func LoadYAMLConfigFiles(globs []string, noCheckPerm bool, out interface{}) (int, error) {
	var filesLoaded int
	for _, fg := range globs {
		files, err := filepath.Glob(fg)
		if err != nil {
			return filesLoaded, err
		}
		for _, file := range files {
			if !noCheckPerm {
				if err := CheckFilePerm(file); err != nil {
					return filesLoaded, err
				}
			}
			configBytes, err := os.ReadFile(file)
			if err != nil {
				return filesLoaded, err
			}
			if err := unmarshalYAMLAppend(configBytes, out, file); err != nil {
				return filesLoaded, err
			}
			filesLoaded++
		}
	}
	return filesLoaded, nil
}

// unmarshalYAMLAppend unmarshals YAML into a slice pointer, appending the result. Sets filename if field exists.
func unmarshalYAMLAppend(data []byte, out interface{}, filename string) error {
	// out must be pointer to slice
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("out must be pointer to slice")
	}
	// Create new element
	elemType := v.Elem().Type().Elem()
	elem := reflect.New(elemType).Interface()
	if err := yaml.Unmarshal(data, elem); err != nil {
		return err
	}
	// If the struct has a field named 'filename', set it
	structVal := reflect.ValueOf(elem).Elem()
	if f := structVal.FieldByName("filename"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
		f.SetString(filename)
	}
	v.Elem().Set(reflect.Append(v.Elem(), structVal))
	return nil
}

// LoadStringAndFileMany loads and decodes multiple base64/raw strings and/or reads multiple files.
// For each string in base64OrRaw, it tries to decode as base64, and falls back to using the raw string if decoding fails.
// For each file in files, it expands variables, resolves relative to baseDir, and reads the file.
// Returns a slice of byte slices (one per input), or error if any file read fails.
func LoadStringAndFileMany(base64OrRaw []string, files []string, vars map[string]string, baseDir string) ([][]byte, error) {
	var all [][]byte
	for _, s := range base64OrRaw {
		if s == "" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// not base64, use as raw string
			data = []byte(s)
		}
		all = append(all, data)
	}
	for _, file := range files {
		if file == "" {
			continue
		}
		file = os.Expand(file, func(placeholderName string) string {
			if v, ok := vars[placeholderName]; ok {
				return v
			}
			return os.Getenv(placeholderName)
		})
		if !filepath.IsAbs(file) && baseDir != "" {
			file = filepath.Join(baseDir, file)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		all = append(all, data)
	}
	return all, nil
}
