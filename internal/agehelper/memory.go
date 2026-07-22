package agehelper

import "golang.org/x/sys/unix"

func disableCoreDumps() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}

func secureLock(value []byte) {
	if len(value) != 0 {
		_ = unix.Mlock(value)
	}
}

func secureClear(value []byte) {
	if len(value) == 0 {
		return
	}
	clear(value)
	_ = unix.Munlock(value)
}

// ClearSecret clears and unlocks a secret returned by Runner. The caller must
// invoke it immediately after forwarding or consuming the file key.
func ClearSecret(value []byte) {
	secureClear(value)
}
