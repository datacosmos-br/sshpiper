package libplugin

import (
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ToInterfaceSlice takes a slice of structs and returns a slice of pointers to those structs as []interface{}.
// Returns empty slice if input is not a slice.
func ToInterfaceSlice(slice interface{}) []interface{} {
	v := reflect.ValueOf(slice)
	if v.Kind() != reflect.Slice {
		log.Errorf("ToInterfaceSlice: input is not a slice (type: %T), returning empty slice", slice)
		return []interface{}{}
	}
	out := make([]interface{}, v.Len())
	for i := 0; i < v.Len(); i++ {
		out[i] = v.Index(i).Addr().Interface()
	}
	return out
}

// MatchUserOrEmpty returns true if candidate == user or candidate is empty.
func MatchUserOrEmpty(candidate, user string) bool {
	return candidate == user || candidate == ""
}

// ResolveTargetUser returns target if not empty, otherwise fallback.
func ResolveTargetUser(target, fallback string) string {
	if target != "" {
		return target
	}
	return fallback
}

// LoadSecretFieldWithFallback tries Vault first, then file, then base64 data.
func LoadSecretFieldWithFallback(vaultPath, field, file, data string, vars map[string]string, dir string) ([]byte, error) {
	if vaultPath != "" {
		v, err := GetVaultSecretField(vaultPath, field)
		if err == nil && len(v) > 0 {
			return v, nil
		}
	}
	return LoadFileOrBase64Many(ListOrString{Str: file}, ListOrString{Str: data}, vars, dir)
}

// BuildKnownHostsFn returns a func that loads known_hosts using file/data/vars/dir.
func BuildKnownHostsFn(file, data string, vars map[string]string, dir string) func(conn ConnMetadata) ([]byte, error) {
	return func(conn ConnMetadata) ([]byte, error) {
		return LoadFileOrBase64Many(ListOrString{Str: file}, ListOrString{Str: data}, vars, dir)
	}
}

// GetPasswordFieldFromSpecs retorna o valor do campo de senha como string pura do primeiro spec que possuir o campo.
func GetPasswordFieldFromSpecs(specs []interface{}, fieldNames []string) (string, error) {
	for _, spec := range specs {
		v := reflect.ValueOf(spec)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		for _, fname := range fieldNames {
			f := v.FieldByName(fname)
			if f.IsValid() && f.Kind() == reflect.String {
				val := f.String()
				if val != "" {
					return val, nil
				}
			}
		}
	}
	return "", nil
}

// ValidateCertificateFromSpecs agrega todas as CA keys dos specs (Vault, arquivo, base64) e chama MatchAndValidateCACert.
func ValidateCertificateFromSpecs(specs []interface{}, conn ConnMetadata, pubKey ssh.PublicKey, dir string, fields []string) error {
	var trustedCAData []byte
	for _, spec := range specs {
		v := reflect.ValueOf(spec)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		vaultField := v.FieldByName("VaultKVPath")
		if vaultField.IsValid() && vaultField.Kind() == reflect.String && vaultField.String() != "" {
			vaultData, err := GetVaultFieldAny(vaultField.String(), fields)
			if err == nil && len(vaultData) > 0 {
				trustedCAData = append(trustedCAData, vaultData...)
				continue
			}
		}
		for _, fname := range fields {
			f := v.FieldByName(fname)
			if f.IsValid() && f.Kind() == reflect.String {
				data, err := LoadFileOrBase64Many(ListOrString{Str: f.String()}, ListOrString{}, map[string]string{"DOWNSTREAM_USER": conn.User()}, dir)
				if err == nil && len(data) > 0 {
					trustedCAData = append(trustedCAData, data...)
				}
			}
		}
	}
	if len(trustedCAData) == 0 {
		return fmt.Errorf("CA not configured or invalid")
	}
	return MatchAndValidateCACert(conn, pubKey, trustedCAData)
}
