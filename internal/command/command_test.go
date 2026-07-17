package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/internal/state"
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
	env := Environment{
		Home:   home,
		Getenv: func(name string) string { return values[name] },
		ProbeYubiKeys: func(context.Context) (int, error) {
			return 1, nil
		},
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"configure"}, &stdout, &stderr, env); code != ExitOK {
		t.Fatalf("configure exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "No PIN was read") {
		t.Fatalf("unexpected configure output: %s", stdout.String())
	}
	logPath := filepath.Join(home, ".ssh", "yubitouch", "yubitouch.log")
	if err := os.WriteFile(logPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
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
	if status.YubiKeyState != "connected" || status.YubiKeyCount != 1 {
		t.Fatalf("YubiKey status = %+v", status)
	}
	if status.DiagnosticLog != logPath || status.LogPermissions != "0600" || status.LogSizeBytes != 3 {
		t.Fatalf("diagnostic log status = %+v", status)
	}
}

func TestYubiKeyStateDistinguishesMissingFromProbeFailure(t *testing.T) {
	state, count := yubiKeyState(0, nil)
	if state != "not_detected" || count != 0 {
		t.Fatalf("missing state = %q, %d", state, count)
	}
	state, count = yubiKeyState(2, errors.New("probe failed"))
	if state != "probe_unavailable" || count != 0 {
		t.Fatalf("failed state = %q, %d", state, count)
	}
}

func TestReportSignFailureMapsSafeExitCodes(t *testing.T) {
	tests := []struct {
		failure string
		code    int
		message string
	}{
		{failure: "device_unavailable", code: ExitDeviceMissing, message: "reconnect"},
		{failure: "provider_initialization", code: ExitPINFailure, message: "PIN/provider"},
		{failure: "key_mismatch", code: ExitKeyMismatch, message: "does not match"},
		{failure: "timeout", code: ExitSignTimeout, message: "timed out"},
		{failure: "canceled", code: ExitSignTimeout, message: "canceled"},
		{failure: "op://Personal/YubiKey/PIN=123456", code: ExitRuntimeError, message: "yubitouch.log"},
	}
	for _, test := range tests {
		t.Run(test.failure, func(t *testing.T) {
			var stderr bytes.Buffer
			code := reportSignFailure(&stderr, test.failure, "/tmp/yubitouch/config.json")
			if code != test.code || !strings.Contains(stderr.String(), test.message) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if strings.Contains(stderr.String(), "op://") || strings.Contains(stderr.String(), "123456") || strings.Contains(stderr.String(), "Personal") {
				t.Fatalf("failure output leaked sensitive text: %s", stderr.String())
			}
		})
	}
}

func TestLastSignFailureClassRejectsStaleState(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	store := state.NewStore(filepath.Join(dir, "state.json"))
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	since := time.Now().UTC()
	store.Handle(signing.Event{
		Type: signing.EventFailure,
		At:   since.Add(-time.Second),
		Err:  errors.New("ssh-add failed"),
	})
	if got := lastSignFailureClass(configPath, since); got != "" {
		t.Fatalf("stale failure class = %q", got)
	}
	store.Handle(signing.Event{
		Type: signing.EventFailure,
		At:   since.Add(time.Second),
		Err:  errors.New("ssh-add failed"),
	})
	if got := lastSignFailureClass(configPath, since); got != "provider_initialization" {
		t.Fatalf("recent failure class = %q", got)
	}
}

func TestMergePersistedStateRejectsStaleRuntimeData(t *testing.T) {
	signAt := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	persisted := state.State{
		PID:           4242,
		ProviderState: "loaded",
		LastSignEvent: "success",
		LastSignAt:    signAt,
	}
	stale := Status{ProviderState: "not_loaded"}
	mergePersistedState(&stale, persisted, false)
	if !stale.StateStale || stale.DaemonPID != 0 || stale.ProviderState != "unavailable" {
		t.Fatalf("stale status = %+v", stale)
	}
	if stale.LastSignEvent != "success" || stale.LastSignAt != signAt.Format(time.RFC3339) {
		t.Fatalf("stale history was not retained: %+v", stale)
	}

	current := Status{ProviderState: "not_loaded"}
	mergePersistedState(&current, persisted, true)
	if current.StateStale || current.DaemonPID != 4242 || current.ProviderState != "loaded" {
		t.Fatalf("current status = %+v", current)
	}
}

func TestProcessAliveRecognizesCurrentProcess(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("current process was reported dead")
	}
	if processAlive(-1) {
		t.Fatal("invalid process was reported alive")
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
