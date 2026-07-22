//go:build !darwin || !cgo

package agehelper

import "errors"

func verifyParentProcess() error {
	return errors.New("age helper parent verification is unavailable")
}

func parentVerificationSupported() bool { return false }
