package libplugin

import (
	"reflect"
)

// GetFieldString safely extracts a string field from a struct using reflection.
// It tries multiple field names and returns the first non-empty value found.
func GetFieldString(obj interface{}, fieldNames ...string) string {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	
	for _, name := range fieldNames {
		field := v.FieldByName(name)
		if !field.IsValid() {
			continue
		}
		
		// Handle string fields
		if field.Kind() == reflect.String {
			if s := field.String(); s != "" {
				return s
			}
		}
		
		// Handle ListOrString type
		if field.Type().Name() == "ListOrString" {
			// Check Str field
			strField := field.FieldByName("Str")
			if strField.IsValid() && strField.Kind() == reflect.String {
				if s := strField.String(); s != "" {
					return s
				}
			}
			// Check List field
			listField := field.FieldByName("List")
			if listField.IsValid() && listField.Kind() == reflect.Slice && listField.Len() > 0 {
				if elem := listField.Index(0); elem.Kind() == reflect.String {
					return elem.String()
				}
			}
		}
	}
	
	return ""
}

// GetFieldBool safely extracts a bool field from a struct using reflection.
// It tries multiple field names and returns true if any field is true.
func GetFieldBool(obj interface{}, fieldNames ...string) bool {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}
	
	for _, name := range fieldNames {
		field := v.FieldByName(name)
		if field.IsValid() && field.Kind() == reflect.Bool && field.Bool() {
			return true
		}
	}
	
	return false
}

// GetFieldListOrString safely extracts all values from a ListOrString field.
func GetFieldListOrString(obj interface{}, fieldName string) []string {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	
	field := v.FieldByName(fieldName)
	if !field.IsValid() {
		return nil
	}
	
	// Handle ListOrString type
	if field.Type().Name() == "ListOrString" {
		var result []string
		
		// Check List field
		listField := field.FieldByName("List")
		if listField.IsValid() && listField.Kind() == reflect.Slice {
			for i := 0; i < listField.Len(); i++ {
				if elem := listField.Index(i); elem.Kind() == reflect.String {
					result = append(result, elem.String())
				}
			}
		}
		
		// Check Str field
		strField := field.FieldByName("Str")
		if strField.IsValid() && strField.Kind() == reflect.String {
			if s := strField.String(); s != "" {
				result = append(result, s)
			}
		}
		
		return result
	}
	
	return nil
}