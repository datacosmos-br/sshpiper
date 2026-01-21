package libplugin

import (
	"reflect"
)

// GetAnnotations returns the annotations map from an object embedding ObjectMeta or with an Annotations field.
// Returns nil if not found or not a map[string]string.
func GetAnnotations(obj any) map[string]string {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	// Try direct field
	f := v.FieldByName("Annotations")
	if f.IsValid() && f.Kind() == reflect.Map && f.Type().Key().Kind() == reflect.String && f.Type().Elem().Kind() == reflect.String {
		return f.Interface().(map[string]string)
	}
	// Try embedded ObjectMeta
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.Struct && field.Type().Name() == "ObjectMeta" {
			f2 := field.FieldByName("Annotations")
			if f2.IsValid() && f2.Kind() == reflect.Map && f2.Type().Key().Kind() == reflect.String && f2.Type().Elem().Kind() == reflect.String {
				return f2.Interface().(map[string]string)
			}
		}
	}
	return nil
}

// ResolveFieldNames returns a list of field names, starting with the annotation override (if present and non-empty), then defaults.
func ResolveFieldNames(annotations map[string]string, annotationKey string, defaults ...string) []string {
	var out []string
	if v, ok := annotations[annotationKey]; ok && v != "" {
		out = append(out, v)
	}
	out = append(out, defaults...)
	return out
}
