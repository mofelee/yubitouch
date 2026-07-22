package config

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/mofelee/yubitouch/internal/ageprofile"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
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

func TestSaveRejectsUnsafeConfigurationLock(t *testing.T) {
	for _, test := range []struct {
		name      string
		makeLock  func(t *testing.T, lockPath string)
		wantError string
	}{
		{
			name: "symlink",
			makeLock: func(t *testing.T, lockPath string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(filepath.Dir(lockPath)), "lock-target")
				if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, lockPath); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "configuration lock",
		},
		{
			name: "permissive permissions",
			makeLock: func(t *testing.T, lockPath string) {
				t.Helper()
				if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(lockPath, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "0600 regular file",
		},
		{
			name: "fifo",
			makeLock: func(t *testing.T, lockPath string) {
				t.Helper()
				if err := unix.Mkfifo(lockPath, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "0600 regular file",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home, cfg := validAgeTestConfig(t)
			path := DefaultPath(home)
			if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
				t.Fatal(err)
			}
			test.makeLock(t, path+".lock")

			err := Save(path, cfg)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("unsafe lock error = %v, want %q", err, test.wantError)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unsafe lock allowed a configuration write: %v", statErr)
			}
		})
	}
}

func TestSaveCreatesPrivateConfigurationLock(t *testing.T) {
	home, cfg := validAgeTestConfig(t)
	path := DefaultPath(home)
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("configuration lock mode = %v, want regular 0600", info.Mode())
	}
}

func TestSignTimeoutLimitAndCheckedMargin(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-timeout-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.SignTimeout = Duration{Duration: MaxSignTimeout}
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatalf("maximum sign timeout was rejected: %v", err)
	}
	cfg.SignTimeout = Duration{Duration: MaxSignTimeout + time.Nanosecond}
	if err := cfg.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), "sign_timeout must not exceed 1h") {
		t.Fatalf("over-limit sign timeout error = %v", err)
	}

	const maxDuration = time.Duration(1<<63 - 1)
	if got, ok := SignTimeoutWithMargin(maxDuration-time.Second, time.Second); !ok || got != maxDuration {
		t.Fatalf("checked timeout at boundary = %s, %v", got, ok)
	}
	for _, test := range []struct {
		timeout time.Duration
		margin  time.Duration
	}{
		{timeout: 0, margin: time.Second},
		{timeout: time.Second, margin: -time.Nanosecond},
		{timeout: maxDuration - time.Second + 1, margin: time.Second},
	} {
		if got, ok := SignTimeoutWithMargin(test.timeout, test.margin); ok || got != 0 {
			t.Fatalf("invalid checked timeout (%s, %s) = %s, %v", test.timeout, test.margin, got, ok)
		}
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

func TestRejectsAgeRecoveryPrivateKeyEnvironment(t *testing.T) {
	for _, name := range []string{
		"YUBITOUCH_AGE_RECOVERY_IDENTITY",
		"YUBITOUCH_AGE_RECOVERY_PRIVATE_KEY",
		"YUBITOUCH_AGE_RECOVERY_SECRET",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			secret := "AGE-SECRET-KEY-1DO-NOT-PERSIST"
			_, err := LoadForConfigure(DefaultPath(home), home, func(got string) string {
				if got == name {
					return secret
				}
				return ""
			})
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("forbidden environment error = %v", err)
			}
			if _, statErr := os.Stat(DefaultPath(home)); !os.IsNotExist(statErr) {
				t.Fatalf("forbidden recovery identity created configuration: %v", statErr)
			}
		})
	}
}

func TestRejectsUnknownAgePrivateKeyFields(t *testing.T) {
	for _, data := range []string{
		`{"age":{"serial":"12345678","slot":"82","algorithm":"x25519","private_key":"secret"}}`,
		`{"age":{"serial":"12345678","slot":"82","algorithm":"x25519","recovery":{"provider":"1password","identity_ref":"op://Personal/item/field","recipient":"age1invalid","identity":"secret"}}}`,
	} {
		var cfg Config
		if err := decodeStrict([]byte(data), &cfg); err == nil {
			t.Fatalf("configuration accepted private key field: %s", data)
		}
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
	if cfg.Age != nil {
		t.Fatalf("default age profile = %+v, want nil", cfg.Age)
	}
	if got := cfg.AgeSocketPath; got != filepath.Join(home, ".ssh", "yubitouch", "age.sock") {
		t.Fatalf("default age socket = %q", got)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "age.sock") || strings.Contains(string(data), `"age"`) {
		t.Fatalf("runtime/default age state was persisted: %s", data)
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
	if cfg.Age != nil || cfg.AgeSocketPath != filepath.Join(runtimeDir, "age.sock") {
		t.Fatalf("legacy age migration = profile %+v socket %q", cfg.Age, cfg.AgeSocketPath)
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

	cfg = Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.Age = &AgeConfig{Serial: "12345678", Slot: "82", Algorithm: "x25519"}
	cfg.AgeSocketPath = cfg.SocketPath
	if err := cfg.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("age socket overlap error = %v", err)
	}
}

func TestAgeEnvironmentCreatesOverridesAndPersistsProfile(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-age-env-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	firstRecipient := generateAgeRecipient(t)
	path := filepath.Join(home, "custom-runtime", "config.json")
	values := map[string]string{
		"YUBITOUCH_PUBLIC_KEY":                keyPath,
		"YUBITOUCH_1PASSWORD_ACCOUNT":         "Personal",
		"YUBITOUCH_AGE_SERIAL":                "12345678",
		"YUBITOUCH_AGE_SLOT":                  "9A",
		"YUBITOUCH_AGE_ALGORITHM":             "x25519",
		"YUBITOUCH_AGE_RECOVERY_PROVIDER":     "1password",
		"YUBITOUCH_AGE_RECOVERY_IDENTITY_REF": "op://Personal/YubiTouch recovery/private-key",
		"YUBITOUCH_AGE_RECOVERY_RECIPIENT":    firstRecipient,
	}
	cfg, err := LoadForConfigure(path, home, func(name string) string { return values[name] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Age == nil || cfg.Age.Recovery == nil {
		t.Fatalf("age environment did not create the profile: %+v", cfg.Age)
	}
	if cfg.Age.Serial != "12345678" || cfg.Age.Slot != "9a" || cfg.Age.Algorithm != "x25519" {
		t.Fatalf("age profile = %+v", cfg.Age)
	}
	if cfg.Age.Recovery.Provider != "1password" || cfg.Age.Recovery.IdentityRef != values["YUBITOUCH_AGE_RECOVERY_IDENTITY_REF"] || cfg.Age.Recovery.Recipient != firstRecipient {
		t.Fatalf("age recovery = %+v", cfg.Age.Recovery)
	}
	wantSocket := filepath.Join(filepath.Dir(path), "age.sock")
	if cfg.AgeSocketPath != wantSocket {
		t.Fatalf("age socket = %q, want %q", cfg.AgeSocketPath, wantSocket)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "age_socket") || strings.Contains(string(persisted), wantSocket) {
		t.Fatalf("runtime age socket was persisted: %s", persisted)
	}

	secondRecipient := generateAgeRecipient(t)
	overrides := map[string]string{
		"YUBITOUCH_AGE_SERIAL":                "87654321",
		"YUBITOUCH_AGE_SLOT":                  "9D",
		"YUBITOUCH_AGE_RECOVERY_IDENTITY_REF": "op://Personal/New recovery/private-key",
		"YUBITOUCH_AGE_RECOVERY_RECIPIENT":    secondRecipient,
	}
	overridden, err := LoadForConfigure(path, home, func(name string) string { return overrides[name] })
	if err != nil {
		t.Fatal(err)
	}
	if overridden.Age.Serial != "87654321" || overridden.Age.Slot != "9d" || overridden.Age.Algorithm != "x25519" {
		t.Fatalf("overridden age profile = %+v", overridden.Age)
	}
	if overridden.Age.Recovery.Provider != "1password" || overridden.Age.Recovery.IdentityRef != overrides["YUBITOUCH_AGE_RECOVERY_IDENTITY_REF"] || overridden.Age.Recovery.Recipient != secondRecipient {
		t.Fatalf("overridden recovery = %+v", overridden.Age.Recovery)
	}
}

func TestAgeEnvironmentOnlyCreatesRequestedSections(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "yt-age-sections-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	base := map[string]string{"YUBITOUCH_PUBLIC_KEY": keyPath}
	cfg, err := LoadForConfigure(DefaultPath(home), home, func(name string) string { return base[name] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Age != nil {
		t.Fatalf("unrequested age profile = %+v", cfg.Age)
	}

	base["YUBITOUCH_AGE_SERIAL"] = "12345678"
	_, err = LoadForConfigure(DefaultPath(home), home, func(name string) string { return base[name] })
	if err == nil || !strings.Contains(err.Error(), "age.slot") {
		t.Fatalf("partial age environment error = %v", err)
	}
}

func TestAgeEnvironmentInvalidatesPublicKeyCacheOnlyWhenTargetChanges(t *testing.T) {
	home, cfg := validAgeTestConfig(t)
	cfg.Age.PublicKey = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	path := DefaultPath(home)
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	unchanged := map[string]string{
		"YUBITOUCH_AGE_SLOT":                  strings.ToUpper(cfg.Age.Slot),
		"YUBITOUCH_AGE_RECOVERY_IDENTITY_REF": "op://Personal/New recovery/private-key",
	}
	loaded, err := LoadForConfigure(path, home, func(name string) string { return unchanged[name] })
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Age.PublicKey != cfg.Age.PublicKey {
		t.Fatal("unchanged target or recovery-only update cleared the public key cache")
	}

	for name, overrides := range map[string]map[string]string{
		"serial": {"YUBITOUCH_AGE_SERIAL": "87654321"},
		"slot":   {"YUBITOUCH_AGE_SLOT": "83"},
	} {
		t.Run(name, func(t *testing.T) {
			updated, err := LoadForConfigure(path, home, func(key string) string { return overrides[key] })
			if err != nil {
				t.Fatal(err)
			}
			if updated.Age.PublicKey != "" {
				t.Fatal("changed hardware target retained the public key cache")
			}
		})
	}
}

func TestAgeValidation(t *testing.T) {
	lowOrderRecipient := lowOrderAgeRecipient(t)
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "empty serial", mutate: func(cfg *Config) { cfg.Age.Serial = "" }, want: "age.serial"},
		{name: "zero serial", mutate: func(cfg *Config) { cfg.Age.Serial = "0" }, want: "age.serial"},
		{name: "noncanonical serial", mutate: func(cfg *Config) { cfg.Age.Serial = "012345678" }, want: "age.serial"},
		{name: "serial whitespace", mutate: func(cfg *Config) { cfg.Age.Serial = " 12345678" }, want: "age.serial"},
		{name: "serial overflow", mutate: func(cfg *Config) { cfg.Age.Serial = "4294967296" }, want: "age.serial"},
		{name: "invalid slot", mutate: func(cfg *Config) { cfg.Age.Slot = "9b" }, want: "age.slot"},
		{name: "slot below range", mutate: func(cfg *Config) { cfg.Age.Slot = "81" }, want: "age.slot"},
		{name: "slot above range", mutate: func(cfg *Config) { cfg.Age.Slot = "96" }, want: "age.slot"},
		{name: "noncanonical slot", mutate: func(cfg *Config) { cfg.Age.Slot = "082" }, want: "age.slot"},
		{name: "invalid algorithm", mutate: func(cfg *Config) { cfg.Age.Algorithm = "X25519" }, want: "age.algorithm"},
		{name: "invalid public key encoding", mutate: func(cfg *Config) { cfg.Age.PublicKey = "not+base64url" }, want: "age.public_key"},
		{name: "invalid public key length", mutate: func(cfg *Config) { cfg.Age.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) }, want: "age.public_key"},
		{name: "padded public key", mutate: func(cfg *Config) { cfg.Age.PublicKey = base64.URLEncoding.EncodeToString(make([]byte, 32)) }, want: "age.public_key"},
		{name: "low-order public key", mutate: func(cfg *Config) { cfg.Age.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }, want: "age.public_key"},
		{name: "invalid provider", mutate: func(cfg *Config) { cfg.Age.Recovery.Provider = "op" }, want: "age.recovery.provider"},
		{name: "missing account", mutate: func(cfg *Config) { cfg.OnePasswordAccount = "" }, want: "onepassword_account"},
		{name: "invalid identity ref", mutate: func(cfg *Config) { cfg.Age.Recovery.IdentityRef = "vault/item/field" }, want: "identity_ref"},
		{name: "identity ref missing field", mutate: func(cfg *Config) { cfg.Age.Recovery.IdentityRef = "op://vault/item" }, want: "identity_ref"},
		{name: "identity ref whitespace", mutate: func(cfg *Config) { cfg.Age.Recovery.IdentityRef = " op://Personal/item/field" }, want: "identity_ref"},
		{name: "invalid recipient", mutate: func(cfg *Config) { cfg.Age.Recovery.Recipient = "age1invalid" }, want: "recipient"},
		{name: "noncanonical recipient", mutate: func(cfg *Config) { cfg.Age.Recovery.Recipient = strings.ToUpper(cfg.Age.Recovery.Recipient) }, want: "recipient"},
		{name: "low-order recipient", mutate: func(cfg *Config) { cfg.Age.Recovery.Recipient = lowOrderRecipient }, want: "recipient"},
		{name: "matching hardware and recovery keys", mutate: func(cfg *Config) {
			publicKey, err := ageprofile.ParseNativeRecipient(cfg.Age.Recovery.Recipient)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Age.PublicKey = base64.RawURLEncoding.EncodeToString(publicKey[:])
		}, want: "independent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home, cfg := validAgeTestConfig(t)
			test.mutate(&cfg)
			if err := cfg.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAgeRecoveryReferenceIsValidatedAtLoadBoundaries(t *testing.T) {
	home, cfg := validAgeTestConfig(t)
	cfg.Age.Recovery.IdentityRef = "op://vault/item"
	path := DefaultPath(home)
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	loaders := map[string]func() error{
		"load": func() error {
			_, err := Load(path, home)
			return err
		},
		"configure": func() error {
			_, err := LoadForConfigure(path, home, func(string) string { return "" })
			return err
		},
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			err := load()
			if err == nil || !strings.Contains(err.Error(), "age.recovery.identity_ref") {
				t.Fatalf("invalid recovery reference error = %v", err)
			}
			if strings.Contains(err.Error(), cfg.Age.Recovery.IdentityRef) {
				t.Fatal("validation error exposed the recovery identity reference")
			}
		})
	}
}

func TestAgeValidSlotsAreCanonicalized(t *testing.T) {
	for _, slot := range []string{"9A", "9c", "9D", "9e", "82", "8A", "8f", "90", "95"} {
		t.Run(slot, func(t *testing.T) {
			home, cfg := validAgeTestConfig(t)
			cfg.Age.Slot = slot
			if err := cfg.ResolveAndValidate(home); err != nil {
				t.Fatal(err)
			}
			if cfg.Age.Slot != strings.ToLower(slot) {
				t.Fatalf("canonical slot = %q", cfg.Age.Slot)
			}
		})
	}
}

func TestAgeWithoutRecoveryDoesNotRequireOnePassword(t *testing.T) {
	home, cfg := validAgeTestConfig(t)
	cfg.Age.Serial = "4294967295"
	cfg.Age.PublicKey = validAgePublicKey(t)
	cfg.Age.Recovery = nil
	cfg.OnePasswordAccount = ""
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}
}

func TestAgePublicKeyIsOptionalAndPersistsCanonically(t *testing.T) {
	home, cfg := validAgeTestConfig(t)
	if cfg.Age.PublicKey != "" {
		t.Fatalf("new age profile public key = %q, want empty", cfg.Age.PublicKey)
	}
	if err := cfg.ResolveAndValidate(home); err != nil {
		t.Fatal(err)
	}

	cfg.Age.PublicKey = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	path := DefaultPath(home)
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Age == nil || loaded.Age.PublicKey != cfg.Age.PublicKey {
		t.Fatalf("persisted age public key = %+v", loaded.Age)
	}
}

func TestAgeSocketLengthIsValidatedOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Unix socket path limit")
	}
	home, cfg := validAgeTestConfig(t)
	cfg.AgeSocketPath = "/" + strings.Repeat("a", 103)
	if err := cfg.ResolveAndValidate(home); err == nil || !strings.Contains(err.Error(), "age socket path is too long") {
		t.Fatalf("age socket length error = %v", err)
	}
}

func validAgeTestConfig(t *testing.T) (string, Config) {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "yt-age-valid-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults(home)
	cfg.PublicKeyPath = keyPath
	cfg.OnePasswordAccount = "Personal"
	cfg.Age = &AgeConfig{
		Serial:    "12345678",
		Slot:      "82",
		Algorithm: "x25519",
		Recovery: &AgeRecovery{
			Provider:    "1password",
			IdentityRef: "op://Personal/YubiTouch recovery/private-key",
			Recipient:   generateAgeRecipient(t),
		},
	}
	return home, cfg
}

func generateAgeRecipient(t *testing.T) string {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity.Recipient().String()
}

func validAgePublicKey(t *testing.T) string {
	t.Helper()
	publicKey, err := ageprofile.ParseNativeRecipient(generateAgeRecipient(t))
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(publicKey[:])
}

func lowOrderAgeRecipient(t *testing.T) string {
	t.Helper()
	publicKey, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := plugin.EncodeX25519Recipient(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}
