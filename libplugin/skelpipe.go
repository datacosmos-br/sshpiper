// Package libplugin provides generic SkelPipe wrappers and aggregation helpers for plugin skeletons.
//
// This file contains:
//   - SkelPipeWrapper, SkelPipeToWrapper, SkelPipeFromWrapper: Generic wrappers for plugin SkelPipe/From/To logic
//   - FromGeneric, ListPipeGeneric: Helpers for constructing SkelPipeFrom/To and SkelPipe lists
//   - AggregateKeysFromSpecs, GetAllAuthorizedKeysFromSpecs, GetAllTrustedUserCAKeysFromSpecs: Key/CA aggregation helpers
//   - TestPasswordFromSpecs: Password aggregation helper
//   - KnownHostsLoader: Loader for known_hosts data from file/base64/Vault
//
// These helpers are used by plugins to implement generic, reusable SkelPipe logic for authentication, key aggregation, and connection handling.
//
// Example usage:
//
//	froms := FromGeneric(plugin, to, fromSpecs, matchConnFn, knownHostsFn)
//	keys, err := GetAllAuthorizedKeysFromSpecs(specs, conn)
package libplugin

// SkelPipeToInterface is a local interface to avoid import cycle
type SkelPipeToInterface interface {
	Host(conn ConnMetadata) string
	User(conn ConnMetadata) string
	IgnoreHostKey(conn ConnMetadata) bool
	KnownHosts(conn ConnMetadata) ([]byte, error)
}

// SkelPipeFromInterface is a local interface to avoid import cycle
type SkelPipeFromInterface interface {
	MatchConn(conn ConnMetadata) (SkelPipeToInterface, error)
}

// SkelPipeInterface is a local interface to avoid import cycle
type SkelPipeInterface interface {
	From() []SkelPipeFromInterface
}

// SkelPipeWrapper is a generic base struct for plugin SkelPipe wrappers.
// It holds references to the plugin instance and the underlying config/pipe object.
//
// Example usage:
//
//	wrapper := SkelPipeWrapper{Plugin: plugin, Pipe: pipe}
type SkelPipeWrapper struct {
	Plugin any
	Pipe   any
}

// NewSkelPipeWrapper constructs a new SkelPipeWrapper.
//
// Example usage:
//
//	wrapper := NewSkelPipeWrapper(plugin, pipe)
func NewSkelPipeWrapper(plugin, pipe any) SkelPipeWrapper {
	return SkelPipeWrapper{
		Plugin: plugin,
		Pipe:   pipe,
	}
}

// SkelPipeToWrapper provides a generic implementation of SkelPipeTo.
//
// Example usage:
//
//	to := NewSkelPipeToWrapper(plugin, pipe, username, hostname, ignoreHostKey, knownHostsFn)
type SkelPipeToWrapper struct {
	SkelPipeWrapper
	Username         string
	Hostname         string
	IgnoreHostKeyVal bool
	KnownHostsFn     func(conn ConnMetadata) ([]byte, error)
}

// NewSkelPipeToWrapper constructs a new SkelPipeToWrapper.
//
// Example usage:
//
//	to := NewSkelPipeToWrapper(plugin, pipe, username, hostname, ignoreHostKey, knownHostsFn)
func NewSkelPipeToWrapper(plugin, pipe any, username, hostname string, ignoreHostKey bool, knownHostsFn func(conn ConnMetadata) ([]byte, error)) SkelPipeToWrapper {
	return SkelPipeToWrapper{
		SkelPipeWrapper:  NewSkelPipeWrapper(plugin, pipe),
		Username:         username,
		Hostname:         hostname,
		IgnoreHostKeyVal: ignoreHostKey,
		KnownHostsFn:     knownHostsFn,
	}
}

// User returns the upstream username.
func (s *SkelPipeToWrapper) User(conn ConnMetadata) string {
	return s.Username
}

// Host returns the upstream host.
func (s *SkelPipeToWrapper) Host(conn ConnMetadata) string {
	return s.Hostname
}

// IgnoreHostKey returns whether to ignore host key checking.
func (s *SkelPipeToWrapper) IgnoreHostKey(conn ConnMetadata) bool {
	return s.IgnoreHostKeyVal
}

// KnownHosts returns the known_hosts data for host key verification.
func (s *SkelPipeToWrapper) KnownHosts(conn ConnMetadata) ([]byte, error) {
	if s.KnownHostsFn != nil {
		return s.KnownHostsFn(conn)
	}
	return nil, nil
}

// SkelPipeFromWrapper provides a generic implementation of SkelPipeFrom.
//
// Example usage:
//
//	from := NewSkelPipeFromWrapper(plugin, pipe, matchConnFn)
type SkelPipeFromWrapper struct {
	SkelPipeWrapper
	MatchConnFn func(conn ConnMetadata) (SkelPipeToInterface, error)
}

// NewSkelPipeFromWrapper constructs a new SkelPipeFromWrapper.
//
// Example usage:
//
//	from := NewSkelPipeFromWrapper(plugin, pipe, matchConnFn)
func NewSkelPipeFromWrapper(plugin, pipe any, matchConnFn func(conn ConnMetadata) (SkelPipeToInterface, error)) SkelPipeFromWrapper {
	return SkelPipeFromWrapper{
		SkelPipeWrapper: NewSkelPipeWrapper(plugin, pipe),
		MatchConnFn:     matchConnFn,
	}
}

// MatchConn delegates to the configured MatchConnFn.
func (s *SkelPipeFromWrapper) MatchConn(conn ConnMetadata) (SkelPipeToInterface, error) {
	if s.MatchConnFn != nil {
		return s.MatchConnFn(conn)
	}
	return nil, nil
}

// FromGeneric constructs SkelPipeFromWrappers for a slice of 'from' specs and a 'to' spec.
// matchConnFn and knownHostsFn are closures for custom logic.
//
// Example usage:
//
//	froms := FromGeneric(plugin, to, fromSpecs, matchConnFn, knownHostsFn)
func FromGeneric(plugin, to any, fromSpecs []any, matchConnFn func(from any, conn ConnMetadata) (SkelPipeToInterface, error), knownHostsFn func(to any, conn ConnMetadata) ([]byte, error)) []SkelPipeFromInterface {
	var froms []SkelPipeFromInterface
	for _, f := range fromSpecs {
		fn := func(conn ConnMetadata) (SkelPipeToInterface, error) {
			return matchConnFn(f, conn)
		}
		from := NewSkelPipeFromWrapper(plugin, f, fn)
		froms = append(froms, &from)
	}
	return froms
}

// ListPipeGeneric wraps a list function to produce []SkelPipe.
//
// Example usage:
//
//	pipes, err := ListPipeGeneric(listFn, pluginCtor)
func ListPipeGeneric(listFn func() ([]any, error), pluginCtor func(any) SkelPipeInterface) ([]SkelPipeInterface, error) {
	pipes, err := listFn()
	if err != nil {
		return nil, err
	}
	var result []SkelPipeInterface
	for _, pipe := range pipes {
		result = append(result, pluginCtor(pipe))
	}
	return result, nil
}

// ExtractSpecs returns a slice of pointers to each element in a slice.
// Useful for plugins to convert a typed slice to []any for generic SkelPipe logic.
func ExtractSpecs[T any](slice []T) []any {
	out := make([]any, len(slice))
	for i := range slice {
		out[i] = &slice[i]
	}
	return out
}
