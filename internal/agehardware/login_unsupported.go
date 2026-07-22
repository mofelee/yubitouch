//go:build !darwin || !cgo

package agehardware

import (
	"errors"

	"github.com/miekg/pkcs11"
)

var errSecureLoginUnavailable = errors.New("secure PKCS#11 login is unavailable")

func secureLoginBytes(string, pkcs11.SessionHandle, uint, []byte) error {
	return errSecureLoginUnavailable
}
