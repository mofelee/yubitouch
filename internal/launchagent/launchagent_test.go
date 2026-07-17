package launchagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"howett.net/plist"
)

func TestWriteLaunchAgent(t *testing.T) {
	home := t.TempDir()
	path, err := Write(home, "/Applications/YubiTouch.app/Contents/MacOS/yubitouch", "/Users/test/.ssh/yubitouch/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if path != PlistPath(home) {
		t.Fatalf("path = %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got launchdPlist
	if _, err := plist.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Label != Label || !got.RunAtLoad || !got.KeepAlive || got.LimitLoadToSessionType != "Aqua" {
		t.Fatalf("unexpected plist: %+v", got)
	}
	wantExecutable := "/Applications/YubiTouch.app/Contents/MacOS/yubitouch"
	if len(got.ProgramArguments) != 4 || got.ProgramArguments[0] != wantExecutable {
		t.Fatalf("arguments = %v", got.ProgramArguments)
	}
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("plist mode = %o, want 644", got)
	}
}

func TestReloadRetriesTransientBootstrapFailure(t *testing.T) {
	original := runLaunchctl
	t.Cleanup(func() { runLaunchctl = original })
	var calls [][]string
	bootstrapAttempts := 0
	runLaunchctl = func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "bootstrap" {
			bootstrapAttempts++
			if bootstrapAttempts < 3 {
				return errors.New("Bootstrap failed: 5: Input/output error")
			}
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Reload(ctx, t.TempDir(), "/Applications/YubiTouch.app/Contents/MacOS/yubitouch", "/tmp/config.json"); err != nil {
		t.Fatal(err)
	}
	wantActions := []string{"bootout", "bootstrap", "bootstrap", "bootstrap", "kickstart"}
	gotActions := make([]string, len(calls))
	for i, call := range calls {
		gotActions[i] = call[0]
	}
	if !reflect.DeepEqual(gotActions, wantActions) {
		t.Fatalf("launchctl actions = %v, want %v", gotActions, wantActions)
	}
}

func TestBootstrapDoesNotRetryPermanentFailure(t *testing.T) {
	original := runLaunchctl
	t.Cleanup(func() { runLaunchctl = original })
	attempts := 0
	runLaunchctl = func(context.Context, ...string) error {
		attempts++
		return errors.New("Bootstrap failed: 78: invalid plist")
	}

	err := bootstrap(context.Background(), "/tmp/invalid.plist")
	if err == nil || attempts != 1 {
		t.Fatalf("bootstrap error = %v, attempts = %d", err, attempts)
	}
}
