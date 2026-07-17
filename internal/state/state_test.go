package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/signing"
)

func TestStoreWritesOnlyClassifiedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore(path)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	store.Handle(signing.Event{Type: signing.EventFailure, At: time.Now(), Err: errors.New("sensitive lower-level detail")})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state mode = %o, want 600", got)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProviderState != "unavailable" || loaded.LastFailureClass != string(signing.EventFailure) {
		t.Fatalf("state = %+v", loaded)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sensitive") {
		t.Fatal("state persisted a lower-level error")
	}
}
