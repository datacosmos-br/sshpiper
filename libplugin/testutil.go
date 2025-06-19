package libplugin

// MockConnMetadata is a reusable mock for ConnMetadata for use in plugin tests.
type MockConnMetadata struct {
	UserVal       string
	RemoteAddrVal string
	UniqueIDVal   string
	Meta          map[string]string
}

func (m *MockConnMetadata) User() string { return m.UserVal }
func (m *MockConnMetadata) RemoteAddr() string {
	if m.RemoteAddrVal != "" {
		return m.RemoteAddrVal
	}
	return "127.0.0.1:2222"
}
func (m *MockConnMetadata) UniqueID() string {
	if m.UniqueIDVal != "" {
		return m.UniqueIDVal
	}
	return "mock-unique-id"
}
func (m *MockConnMetadata) GetMeta(key string) string {
	if m.Meta != nil {
		return m.Meta[key]
	}
	return ""
}
