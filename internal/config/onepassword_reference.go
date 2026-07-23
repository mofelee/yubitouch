package config

import (
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxOnePasswordSecretReferenceLength = 4096

var errInvalidOnePasswordSecretReference = errors.New("1Password secret reference syntax is invalid")

// ValidateOnePasswordSecretReference accepts a direct 1Password field
// reference without resolving it or initializing the SDK's WASM runtime.
func ValidateOnePasswordSecretReference(reference string) error {
	if reference == "" || len(reference) > maxOnePasswordSecretReferenceLength ||
		!utf8.ValidString(reference) || strings.TrimSpace(reference) != reference ||
		!strings.HasPrefix(reference, "op://") {
		return errInvalidOnePasswordSecretReference
	}

	path := strings.TrimPrefix(reference, "op://")
	if strings.ContainsAny(path, "?#") {
		return errInvalidOnePasswordSecretReference
	}
	parts := strings.Split(path, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return errInvalidOnePasswordSecretReference
	}
	for _, part := range parts {
		if part == "" {
			return errInvalidOnePasswordSecretReference
		}
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || !utf8.ValidString(decoded) ||
			strings.TrimSpace(decoded) != decoded || containsReferenceControl(decoded) {
			return errInvalidOnePasswordSecretReference
		}
	}
	return nil
}

func containsReferenceControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
