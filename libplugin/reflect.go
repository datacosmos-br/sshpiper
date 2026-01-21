package libplugin

import (
	"fmt"
)

// FieldGetter defines interface for structs that can provide field values
type FieldGetter interface {
	GetField(fieldName string) (interface{}, error)
}

// StringGetter defines interface for structs that can provide string values
type StringGetter interface {
	GetString(fieldName string) (string, error)
}

// BoolGetter defines interface for structs that can provide bool values
type BoolGetter interface {
	GetBool(fieldName string) (bool, error)
}

// ListStringGetter defines interface for structs that can provide string lists
type ListStringGetter interface {
	GetStringList(fieldName string) ([]string, error)
}

// GetFieldString safely extracts a string field using proper interfaces.
// This replaces the previous reflection-based implementation.
func GetFieldString(obj interface{}, fieldNames ...string) string {
	// Try StringGetter interface first (preferred)
	if getter, ok := obj.(StringGetter); ok {
		for _, name := range fieldNames {
			if val, err := getter.GetString(name); err == nil && val != "" {
				return val
			}
		}
	}

	// Try FieldGetter interface as fallback
	if getter, ok := obj.(FieldGetter); ok {
		for _, name := range fieldNames {
			if val, err := getter.GetField(name); err == nil {
				if str, ok := val.(string); ok && str != "" {
					return str
				}
			}
		}
	}

	// If no interface implemented, check if it's a ListOrString directly
	if los, ok := obj.(ListOrString); ok {
		if los.Str != "" {
			return los.Str
		}
		if len(los.List) > 0 {
			return los.List[0]
		}
	}

	return ""
}

// GetFieldBool safely extracts a bool field using proper interfaces.
// This replaces the previous reflection-based implementation.
func GetFieldBool(obj interface{}, fieldNames ...string) bool {
	// Try BoolGetter interface first (preferred)
	if getter, ok := obj.(BoolGetter); ok {
		for _, name := range fieldNames {
			if val, err := getter.GetBool(name); err == nil && val {
				return true
			}
		}
	}

	// Try FieldGetter interface as fallback
	if getter, ok := obj.(FieldGetter); ok {
		for _, name := range fieldNames {
			if val, err := getter.GetField(name); err == nil {
				if b, ok := val.(bool); ok && b {
					return true
				}
			}
		}
	}

	return false
}

// GetFieldListOrString safely extracts all values from a ListOrString field.
// This replaces the previous reflection-based implementation.
func GetFieldListOrString(obj interface{}, fieldName string) []string {
	// Try ListStringGetter interface first (preferred)
	if getter, ok := obj.(ListStringGetter); ok {
		if val, err := getter.GetStringList(fieldName); err == nil {
			return val
		}
	}

	// Try FieldGetter interface as fallback
	if getter, ok := obj.(FieldGetter); ok {
		if val, err := getter.GetField(fieldName); err == nil {
			if los, ok := val.(ListOrString); ok {
				var result []string
				result = append(result, los.List...)
				if los.Str != "" {
					result = append(result, los.Str)
				}
				return result
			}
		}
	}

	// If obj is directly a ListOrString
	if los, ok := obj.(ListOrString); ok {
		var result []string
		result = append(result, los.List...)
		if los.Str != "" {
			result = append(result, los.Str)
		}
		return result
	}

	return nil
}

// SafeFieldAccess provides a safer way to access fields with proper error handling
type SafeFieldAccess struct {
	obj interface{}
}

// NewSafeFieldAccess creates a new SafeFieldAccess wrapper
func NewSafeFieldAccess(obj interface{}) *SafeFieldAccess {
	return &SafeFieldAccess{obj: obj}
}

// String attempts to get a string field value with proper error handling
func (s *SafeFieldAccess) String(fieldNames ...string) (string, error) {
	val := GetFieldString(s.obj, fieldNames...)
	if val == "" {
		return "", fmt.Errorf("no non-empty string field found among: %v", fieldNames)
	}
	return val, nil
}

// Bool attempts to get a bool field value with proper error handling
func (s *SafeFieldAccess) Bool(fieldNames ...string) (bool, error) {
	if getter, ok := s.obj.(BoolGetter); ok {
		for _, name := range fieldNames {
			if val, err := getter.GetBool(name); err == nil {
				return val, nil
			}
		}
	}
	return false, fmt.Errorf("no bool field found among: %v", fieldNames)
}

// StringList attempts to get a string list field value with proper error handling
func (s *SafeFieldAccess) StringList(fieldName string) ([]string, error) {
	val := GetFieldListOrString(s.obj, fieldName)
	if val == nil {
		return nil, fmt.Errorf("field %s not found or not a string list", fieldName)
	}
	return val, nil
}
