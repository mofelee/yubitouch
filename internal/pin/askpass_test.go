package pin

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestClaimGuardIsOneShot(t *testing.T) {
	guard := filepath.Join(t.TempDir(), "guard")
	if err := claimGuard(guard); err != nil {
		t.Fatal(err)
	}
	if err := claimGuard(guard); err == nil {
		t.Fatal("guard allowed a second attempt")
	}
	info, err := os.Stat(guard)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("guard mode = %o, want 600", got)
	}
}

func TestAskPassRejectsUnexpectedPromptBeforeReadingConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := RunAskPass(t.Context(), "Enter passphrase for a file:", &stdout, &stderr, t.TempDir(), func(string) string { return "" })
	if code != 4 {
		t.Fatalf("exit = %d, want 4", code)
	}
	if stdout.Len() != 0 {
		t.Fatal("unexpected prompt wrote a response")
	}
}
