package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG2Lg3xFnLvrY1W8yZOQ1q0+toWPZyV4lX5JUKbVwS3p test\n"

func TestLoadForConfigureAndSave(t *testing.T) {
	home := t.TempDir()
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o644); err != nil {
		t.Fatal(err)
	}
	providerTarget := filepath.Join(home, "libykcs11.1.dylib")
	providerLink := filepath.Join(home, "libykcs11.dylib")
	if err := os.WriteFile(providerTarget, []byte("provider"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(providerTarget), providerLink); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"YUBITOUCH_PUBLIC_KEY":        keyPath,
		"YUBITOUCH_PIN_PROVIDER":      "1password",
		"YUBITOUCH_1PASSWORD_ACCOUNT": "Personal",
		"YUBITOUCH_1PASSWORD_REF":     "op://Personal/YubiKey/pin",
		"YUBITOUCH_SIGN_TIMEOUT":      "15s",
		"YUBITOUCH_SOCKET":            filepath.Join("/tmp", "yt-config-test-agent.sock"),
		"YUBITOUCH_BACKEND_SOCKET":    filepath.Join("/tmp", "yt-config-test-backend.sock"),
		"YUBITOUCH_YKCS11":            providerLink,
	}
	getenv := func(name string) string { return values[name] }
	path := DefaultPath(home)

	cfg, err := LoadForConfigure(path, home, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SignTimeout.Duration != 15*time.Second {
		t.Fatalf("unexpected timeout: %s", cfg.SignTimeout.Duration)
	}
	if cfg.Fingerprint() != ssh.FingerprintSHA256(cfg.PublicKey) || cfg.Fingerprint() == "" {
		t.Fatal("missing public key fingerprint")
	}
	if cfg.YKCS11Path != providerLink {
		t.Fatalf("provider path was resolved before persistence: %q", cfg.YKCS11Path)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
	loaded, err := Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.OnePasswordRef != values["YUBITOUCH_1PASSWORD_REF"] {
		t.Fatalf("reference was not persisted")
	}
	if loaded.Fingerprint() != cfg.Fingerprint() {
		t.Fatalf("fingerprint changed after reload")
	}
	if loaded.YKCS11Path != providerLink {
		t.Fatalf("stable provider path was not persisted: %q", loaded.YKCS11Path)
	}
}

func TestRejectsPINField(t *testing.T) {
	home := t.TempDir()
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o644); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"pin":"123456","public_key":"` + keyPath + `"}`)
	var cfg Config
	if err := decodeStrict(data, &cfg); err == nil {
		t.Fatal("config unexpectedly accepted a PIN field")
	}
}

func TestRejectsPINEnvironment(t *testing.T) {
	home := t.TempDir()
	_, err := LoadForConfigure(DefaultPath(home), home, func(name string) string {
		if name == "YUBITOUCH_PIN" {
			return "123456"
		}
		return ""
	})
	if err == nil {
		t.Fatal("configuration unexpectedly accepted YUBITOUCH_PIN")
	}
}

func TestLoadRejectsPermissiveConfig(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, home); err == nil {
		t.Fatal("Load unexpectedly accepted a 0644 configuration")
	}
}

func TestEnsurePrivateDirRepairsPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("runtime mode = %o, want 700", got)
	}
}

func TestStableYKCS11PathMigratesHomebrewCellarPaths(t *testing.T) {
	tests := map[string]string{
		"/opt/homebrew/Cellar/yubico-piv-tool/2.7.2/lib/libykcs11.2.dylib": "/opt/homebrew/opt/yubico-piv-tool/lib/libykcs11.dylib",
		"/usr/local/Cellar/yubico-piv-tool/2.7.2/lib/libykcs11.dylib":      "/usr/local/opt/yubico-piv-tool/lib/libykcs11.dylib",
		"/custom/security/libykcs11.dylib":                                 "/custom/security/libykcs11.dylib",
	}
	for input, want := range tests {
		if got := stableYKCS11Path(input); got != want {
			t.Fatalf("stableYKCS11Path(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDefaultsKeepStableProviderPath(t *testing.T) {
	path := Defaults(t.TempDir()).YKCS11Path
	if strings.Contains(path, string(filepath.Separator)+"Cellar"+string(filepath.Separator)) {
		t.Fatalf("default provider path is versioned: %s", path)
	}
}

func TestOnePasswordFallbackUsesDefaultSocketAndPersists(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-cfg-fallback-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"YUBITOUCH_PUBLIC_KEY":     keyPath,
		"YUBITOUCH_FALLBACK_AGENT": "1password",
	}
	cfg, err := LoadForConfigure(DefaultPath(home), home, func(name string) string { return values[name] })
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "Library", "Group Containers", "2BUA8C4S2C.com.1password", "t", "agent.sock")
	if cfg.FallbackAgent != FallbackAgent1Password || cfg.FallbackAgentSocket != want {
		t.Fatalf("fallback = %q %q, want 1password %q", cfg.FallbackAgent, cfg.FallbackAgentSocket, want)
	}
}

func TestFallbackConfigurationRejectsInvalidAndManagedSockets(t *testing.T) {
	home := t.TempDir()
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	base := Defaults(home)
	base.PublicKeyPath = keyPath

	invalid := base
	invalid.FallbackAgent = "other"
	if err := invalid.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), "invalid fallback_agent") {
		t.Fatalf("invalid fallback error = %v", err)
	}

	loop := base
	loop.FallbackAgent = FallbackAgent1Password
	loop.FallbackAgentSocket = loop.SocketPath
	if err := loop.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("managed socket fallback error = %v", err)
	}
}

func TestFallbackCanBeDisabledFromEnvironment(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-cfg-disable-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	path := DefaultPath(home)
	cfg := Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.FallbackAgent = FallbackAgent1Password
	cfg.FallbackAgentSocket = filepath.Join(home, "fallback.sock")
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadForConfigure(path, home, func(name string) string {
		if name == "YUBITOUCH_FALLBACK_AGENT" {
			return "none"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.FallbackAgent != FallbackAgentNone || loaded.FallbackAgentSocket != "" {
		t.Fatalf("fallback was not disabled: %+v", loaded)
	}
}
