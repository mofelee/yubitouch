package launchagent

import (
	"os"
	"path/filepath"
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
