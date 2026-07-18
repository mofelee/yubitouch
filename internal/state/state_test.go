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
	store.Handle(signing.Event{
		Type: signing.EventFailure,
		At:   time.Now(),
		Err:  errors.New("sensitive lower-level detail"),
		Requester: signing.Requester{
			Name:             "Sensitive Requester",
			DirectClient:     "private-client",
			BundleIdentifier: "com.example.private",
		},
	})

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
	if loaded.ProviderState != "unavailable" || loaded.LastFailureClass != "internal" {
		t.Fatalf("state = %+v", loaded)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(data)
	if strings.Contains(contents, "sensitive") || strings.Contains(contents, "Sensitive Requester") ||
		strings.Contains(contents, "private-client") || strings.Contains(contents, "com.example.private") {
		t.Fatal("state persisted lower-level or requester identity data")
	}
}

func TestStorePersistsCanceledTerminalState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore(path)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	store.Handle(signing.Event{Type: signing.EventCanceled, At: time.Now(), Err: signing.ErrCanceled})
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastSignEvent != string(signing.EventCanceled) ||
		loaded.LastFailureClass != "canceled" ||
		loaded.ProviderState != "unavailable" {
		t.Fatalf("canceled state = %+v", loaded)
	}
}
