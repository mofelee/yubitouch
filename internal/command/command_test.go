package command

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG2Lg3xFnLvrY1W8yZOQ1q0+toWPZyV4lX5JUKbVwS3p test\n"

func TestConfigureAndStatusJSON(t *testing.T) {
	home := t.TempDir()
	keyPath := filepath.Join(home, "key.pub")
	if err := os.WriteFile(keyPath, []byte(testPublicKey), 0o644); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"YUBITOUCH_PUBLIC_KEY":     keyPath,
		"YUBITOUCH_SOCKET":         filepath.Join("/tmp", "yt-command-test-agent.sock"),
		"YUBITOUCH_BACKEND_SOCKET": filepath.Join("/tmp", "yt-command-test-backend.sock"),
	}
	env := Environment{Home: home, Getenv: func(name string) string { return values[name] }}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"configure"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("configure exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No PIN was read") {
		t.Fatalf("unexpected configure output: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"status", "--json"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("status exit %d: %s", code, stderr.String())
	}
	var status Status
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Configured || status.PublicKey == "" {
		t.Fatalf("incomplete status: %+v", status)
	}
	if status.ProviderState != "not_loaded" {
		t.Fatalf("provider state = %q", status.ProviderState)
	}
}

func TestMissingConfigIsConfigError(t *testing.T) {
	env := Environment{Home: t.TempDir(), Getenv: func(string) string { return "" }}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"status"}, &stdout, &stderr, env); code != ExitConfigError {
		t.Fatalf("status exit %d, want %d", code, ExitConfigError)
	}
	if !strings.Contains(stderr.String(), "not configured") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}
