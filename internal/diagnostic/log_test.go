package diagnostic

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/signing"
)

func TestStructuredLogIsPrivateAndDoesNotPersistErrorText(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	path := filepath.Join(dir, "yubitouch.log")
	logger, err := Open(path, "info")
	if err != nil {
		t.Fatal(err)
	}
	logger.now = func() time.Time { return time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC) }
	sink := NewSigningSink(logger)
	sink.Handle(signing.Event{
		Type: signing.EventFailure,
		At:   time.Now(),
		Err:  errors.New("op://Personal/YubiKey/PIN contained 123456"),
		Requester: signing.Requester{
			Name:             "Sensitive Requester",
			DirectClient:     "private-client",
			BundleIdentifier: "com.example.private",
		},
	})
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("log mode = %o, want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(data)
	if strings.Contains(contents, "op://") || strings.Contains(contents, "123456") || strings.Contains(contents, "Personal") ||
		strings.Contains(contents, "Sensitive Requester") || strings.Contains(contents, "private-client") || strings.Contains(contents, "com.example.private") {
		t.Fatalf("log persisted sensitive error text: %s", contents)
	}
	if !strings.Contains(contents, `"event":"sign_failed"`) || !strings.Contains(contents, `"failure_class":"internal"`) {
		t.Fatalf("log does not contain the classified event: %s", contents)
	}
}

func TestLogLevelFiltersInformationalEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yubitouch.log")
	logger, err := Open(path, "error")
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(LevelInfo, EventDaemonStarted, FailureNone); err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(LevelError, EventDaemonFailed, FailureInternal); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(data)
	if strings.Contains(contents, string(EventDaemonStarted)) || !strings.Contains(contents, string(EventDaemonFailed)) {
		t.Fatalf("unexpected filtered log: %s", contents)
	}
}

func TestSigningSinkRecordsClassifiedCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yubitouch.log")
	logger, err := Open(path, "info")
	if err != nil {
		t.Fatal(err)
	}
	NewSigningSink(logger).Handle(signing.Event{Type: signing.EventCanceled, Err: signing.ErrCanceled})
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(data)
	if !strings.Contains(contents, `"event":"sign_canceled"`) || !strings.Contains(contents, `"failure_class":"canceled"`) {
		t.Fatalf("cancellation was not classified: %s", contents)
	}
}

func TestClassifyTypedDeviceUnavailable(t *testing.T) {
	err := fmt.Errorf("sign failed: %w", signing.ErrDeviceUnavailable)
	if got := Classify(err); got != FailureDeviceUnavailable {
		t.Fatalf("failure class = %q, want %q", got, FailureDeviceUnavailable)
	}
}

func TestLogResetsAtSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yubitouch.log")
	logger, err := Open(path, "info")
	if err != nil {
		t.Fatal(err)
	}
	logger.maxBytes = 250
	for range 10 {
		if err := logger.Write(LevelInfo, EventSignInitializing, FailureNone); err != nil {
			t.Fatal(err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 400 {
		t.Fatalf("bounded log grew to %d bytes", info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), string(EventLogReset)) {
		t.Fatalf("log did not record a size reset: %s", data)
	}
}

func TestOpenRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "yubitouch.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "info"); err == nil {
		t.Fatal("Open accepted a symlink")
	}
}

func TestLoggerRejectsUnclassifiedStrings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yubitouch.log")
	logger, err := Open(path, "debug")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	if err := logger.Write(LevelInfo, Event("op://vault/item/pin"), FailureNone); err == nil {
		t.Fatal("logger accepted an arbitrary event")
	}
	if err := logger.Write(LevelError, EventSignFailed, FailureClass("123456")); err == nil {
		t.Fatal("logger accepted an arbitrary failure class")
	}
}
