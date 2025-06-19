package libplugin

import (
	"fmt"
	"reflect"
)

// ValidateRequiredFields checks that all required fields are non-empty in a struct.
// Returns an error if any field is missing or empty.
func ValidateRequiredFields(obj interface{}, fields ...string) error {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	for _, field := range fields {
		f := v.FieldByName(field)
		if !f.IsValid() || (f.Kind() == reflect.String && f.String() == "") {
			return fmt.Errorf("missing required field: %s", field)
		}
	}
	return nil
}
