//go:build darwin && cgo

package agehelper

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	hardenedParentHarnessEnvironment  = "YUBITOUCH_TEST_HARDENED_PARENT"
	hardenedParentExpectedEnvironment = "YUBITOUCH_TEST_HARDENED_PARENT_EXPECTED"
)

func TestHardenedParentHarness(t *testing.T) {
	if os.Getenv(hardenedParentHarnessEnvironment) != "1" {
		t.Skip("internal hardened parent harness")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), parentAuthChildPrefix+"hardened")
	var input bytes.Buffer
	if err := writeFrame(&input, []byte{0}, maxRequestFrame); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable)
	parentWatch, parentAlive, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer parentWatch.Close()
	defer parentAlive.Close()
	continueRead, continueWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer continueRead.Close()
	defer continueWrite.Close()
	cmd.ExtraFiles = []*os.File{parentWatch, continueRead}
	configureHelperProcess(cmd)
	cmd.Env = []string{
		"HOME=" + home,
		internalModeEnvironment + "=" + string(ModeHardware),
		parentWatchEnvironment + "=3",
		hardwareContinueEnvironment + "=4",
		"YUBITOUCH_CONFIG=" + configPath,
	}
	cmd.Stdin = &input
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		t.Fatal("helper unexpectedly accepted an empty request")
	}
	want := ErrorInvalidRequest
	if os.Getenv(hardenedParentExpectedEnvironment) == string(ErrorHelper) {
		want = ErrorHelper
	}
	if class := responseErrorClass(t, &output); class != want {
		t.Fatalf("error class = %q, want %q", class, want)
	}
}

func TestParentVerificationRejectsUnsafeRuntimeEntitlements(t *testing.T) {
	if os.Getenv(hardenedParentHarnessEnvironment) != "" {
		t.Skip("outer hardening test only")
	}
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign is unavailable")
	}

	for _, entitlement := range []string{
		"com.apple.security.cs.allow-dyld-environment-variables",
		"com.apple.security.get-task-allow",
	} {
		t.Run(entitlement, func(t *testing.T) {
			dir := t.TempDir()
			signedExecutable := filepath.Join(dir, "agehelper-unsafe.test")
			copyExecutable(t, signedExecutable)
			entitlementsPath := filepath.Join(dir, "unsafe.entitlements")
			entitlements := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>` + entitlement + `</key><true/></dict></plist>
`
			if err := os.WriteFile(entitlementsPath, []byte(entitlements), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(
				"/usr/bin/codesign", "--force", "--options", "runtime", "--entitlements", entitlementsPath,
				"--sign", "-", signedExecutable,
			).CombinedOutput()
			if err != nil {
				t.Fatalf("unsafe test signing failed: %v: %s", err, output)
			}

			cmd := exec.Command(signedExecutable, "-test.run=^TestHardenedParentHarness$", "-test.v=false")
			cmd.Env = hardeningTestEnvironment("", "")
			cmd.Env = append(cmd.Env, hardenedParentExpectedEnvironment+"="+string(ErrorHelper))
			output, err = cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("unsafe entitlement rejection harness failed: %v: %s", err, output)
			}
		})
	}
}

func TestHardenedRuntimeBlocksInjectedParent(t *testing.T) {
	if os.Getenv(hardenedParentHarnessEnvironment) != "" {
		t.Skip("outer hardening test only")
	}
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is unavailable")
	}
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign is unavailable")
	}

	dir := t.TempDir()
	signedExecutable := filepath.Join(dir, "agehelper-hardened.test")
	copyExecutable(t, signedExecutable)
	entitlements, err := filepath.Abs(filepath.Join("..", "..", "packaging", "YubiTouch.entitlements"))
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(
		"/usr/bin/codesign", "--force", "--options", "runtime", "--entitlements", entitlements,
		"--sign", "-", signedExecutable,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("ad-hoc runtime signing failed: %v: %s", err, output)
	}
	signingInfo, err := exec.Command(
		"/usr/bin/codesign", "--display", "--verbose=4", "--entitlements", ":-", signedExecutable,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("cannot inspect hardened test signature: %v: %s", err, signingInfo)
	}
	info := string(signingInfo)
	if !strings.Contains(info, "runtime") ||
		!strings.Contains(info, "com.apple.security.cs.disable-library-validation") ||
		strings.Contains(info, "com.apple.security.cs.allow-dyld-environment-variables") ||
		strings.Contains(info, "com.apple.security.get-task-allow") {
		t.Fatal("hardened test signature has unexpected flags or entitlements")
	}

	sourcePath := filepath.Join(dir, "inject.c")
	dylibPath := filepath.Join(dir, "inject.dylib")
	markerPath := filepath.Join(dir, "injected")
	source := `
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void yubitouch_test_injected(void) {
    const char *path = getenv("YUBITOUCH_TEST_INJECTION_MARKER");
    if (path == NULL) {
        return;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        close(fd);
    }
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = exec.Command(clang, "-dynamiclib", "-Wall", "-Werror", "-o", dylibPath, sourcePath).CombinedOutput()
	if err != nil {
		t.Fatalf("injection test dylib build failed: %v: %s", err, output)
	}

	cmd := exec.Command(signedExecutable, "-test.run=^TestHardenedParentHarness$", "-test.v=false")
	cmd.Env = hardeningTestEnvironment(dylibPath, markerPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hardened parent harness failed: %v: %s", err, output)
	}
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("DYLD injection reached the hardened parent: %v", err)
	}
}

func copyExecutable(t *testing.T, destination string) {
	t.Helper()
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destinationFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destinationFile, source); err != nil {
		destinationFile.Close()
		t.Fatal(err)
	}
	if err := destinationFile.Close(); err != nil {
		t.Fatal(err)
	}
}

func hardeningTestEnvironment(dylibPath, markerPath string) []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == hardenedParentHarnessEnvironment || name == hardenedParentExpectedEnvironment ||
			name == "DYLD_INSERT_LIBRARIES" || name == "YUBITOUCH_TEST_INJECTION_MARKER" {
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment, hardenedParentHarnessEnvironment+"=1")
	if dylibPath != "" {
		environment = append(environment, "DYLD_INSERT_LIBRARIES="+dylibPath)
	}
	if markerPath != "" {
		environment = append(environment, "YUBITOUCH_TEST_INJECTION_MARKER="+markerPath)
	}
	return environment
}
