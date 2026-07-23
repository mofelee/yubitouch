//go:build darwin && cgo

package config

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const hardenedReferenceValidationEnvironment = "YUBITOUCH_TEST_HARDENED_REFERENCE_VALIDATION"

func TestOnePasswordReferenceValidationDoesNotRequireExecutableMemory(t *testing.T) {
	if os.Getenv(hardenedReferenceValidationEnvironment) == "1" {
		if err := ValidateOnePasswordSecretReference("op://vault/item/field"); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign is unavailable")
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	signedExecutable := filepath.Join(t.TempDir(), "config-reference-hardened.test")
	copyReferenceTestExecutable(t, executable, signedExecutable)
	output, err := exec.Command(
		"/usr/bin/codesign", "--force", "--options", "runtime", "--sign", "-", signedExecutable,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("hardened test signing failed: %v: %s", err, output)
	}

	command := exec.Command(
		signedExecutable,
		"-test.run=^TestOnePasswordReferenceValidationDoesNotRequireExecutableMemory$",
		"-test.v=false",
	)
	command.Env = []string{
		"HOME=" + t.TempDir(),
		"PATH=/usr/bin:/bin",
		hardenedReferenceValidationEnvironment + "=1",
	}
	if output, err = command.CombinedOutput(); err != nil {
		t.Fatalf("hardened reference validation failed: %v: %s", err, output)
	}
}

func copyReferenceTestExecutable(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}
