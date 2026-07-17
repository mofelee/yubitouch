package config

import (
	"os"
	"path/filepath"
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
	values := map[string]string{
		"YUBITOUCH_PUBLIC_KEY":        keyPath,
		"YUBITOUCH_PIN_PROVIDER":      "1password",
		"YUBITOUCH_1PASSWORD_ACCOUNT": "Personal",
		"YUBITOUCH_1PASSWORD_REF":     "op://Personal/YubiKey/pin",
		"YUBITOUCH_SIGN_TIMEOUT":      "15s",
		"YUBITOUCH_SOCKET":            filepath.Join("/tmp", "yt-config-test-agent.sock"),
		"YUBITOUCH_BACKEND_SOCKET":    filepath.Join("/tmp", "yt-config-test-backend.sock"),
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
