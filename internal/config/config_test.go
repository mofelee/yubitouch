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
		"YUBITOUCH_PIV_SOCKET":        filepath.Join("/tmp", "yt-config-test-piv.sock"),
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

func TestDefaultsUseSeparatePIVRouteAndDisableFallback(t *testing.T) {
	home := t.TempDir()
	cfg := Defaults(home)
	if cfg.FallbackAgent != FallbackAgentNone || cfg.FallbackAgentSocket != "" {
		t.Fatalf("fallback defaults = %q %q", cfg.FallbackAgent, cfg.FallbackAgentSocket)
	}
	if cfg.SocketPath == cfg.PIVSocketPath || cfg.SocketPath == cfg.BackendSocketPath || cfg.PIVSocketPath == cfg.BackendSocketPath {
		t.Fatalf("managed sockets are not distinct: %+v", cfg)
	}
	if got := filepath.Base(cfg.PIVSocketPath); got != "piv-agent.sock" {
		t.Fatalf("PIV socket basename = %q", got)
	}
}

func TestLoadMigratesConfigWithoutPIVSocket(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-config-migrate-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	runtimeDir := filepath.Join(home, ".ssh", "yubitouch")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runtimeDir, "config.json")
	legacy := `{
  "pin_provider": "prompt",
  "public_key": "` + keyPath + `",
  "ykcs11": "/tmp/libykcs11.dylib",
  "openssh_prefix": "/tmp/openssh",
  "socket": "/tmp/yubitouch-legacy-agent.sock",
  "backend_socket": "/tmp/yubitouch-legacy-backend.sock",
  "fallback_agent": "1password",
  "fallback_agent_socket": "/tmp/yubitouch-legacy-1password.sock",
  "sound": "Glass",
  "sign_timeout": "60s",
  "log_level": "info"
}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(runtimeDir, "piv-agent.sock")
	if cfg.PIVSocketPath != want {
		t.Fatalf("migrated PIV socket = %q, want %q", cfg.PIVSocketPath, want)
	}
	if cfg.FallbackAgent != FallbackAgent1Password || cfg.FallbackAgentSocket != "/tmp/yubitouch-legacy-1password.sock" {
		t.Fatalf("legacy fallback was not retained: %q %q", cfg.FallbackAgent, cfg.FallbackAgentSocket)
	}
}

func TestFallbackEnvironmentEnablesAndDisablesWithoutLosingManagedTarget(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-config-fallback-")
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
		"YUBITOUCH_SOCKET":         "/tmp/yubitouch-fallback-public.sock",
		"YUBITOUCH_PIV_SOCKET":     "/tmp/yubitouch-fallback-piv.sock",
		"YUBITOUCH_BACKEND_SOCKET": "/tmp/yubitouch-fallback-backend.sock",
		"YUBITOUCH_FALLBACK_AGENT": "1password",
	}
	cfg, err := LoadForConfigure(DefaultPath(home), home, func(name string) string { return values[name] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FallbackAgent != FallbackAgent1Password || cfg.FallbackAgentSocket != defaultOnePasswordAgentSocket(home) {
		t.Fatalf("enabled fallback = %q %q", cfg.FallbackAgent, cfg.FallbackAgentSocket)
	}
	if err := Save(DefaultPath(home), cfg); err != nil {
		t.Fatal(err)
	}
	disabled, err := LoadForConfigure(DefaultPath(home), home, func(name string) string {
		if name == "YUBITOUCH_FALLBACK_AGENT" {
			return "off"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.FallbackAgent != FallbackAgentNone || disabled.FallbackAgentSocket != cfg.FallbackAgentSocket {
		t.Fatalf("disabled fallback = %q %q", disabled.FallbackAgent, disabled.FallbackAgentSocket)
	}
}

func TestResolveRejectsOverlappingManagedSockets(t *testing.T) {
	home := t.TempDir()
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.PIVSocketPath = cfg.SocketPath
	if err := cfg.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("overlapping sockets error = %v", err)
	}

	cfg = Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.FallbackAgent = FallbackAgent1Password
	cfg.FallbackAgentSocket = cfg.BackendSocketPath
	if err := cfg.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), "fallback_agent_socket") {
		t.Fatalf("fallback overlap error = %v", err)
	}
}
