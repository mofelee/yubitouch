package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/ageipc"
	"github.com/mofelee/yubitouch/internal/agentroute"
	"github.com/mofelee/yubitouch/internal/ageservice"
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

func TestStoreKeepsAgeStateSeparateFromSSHSigningState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore(path)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	store.Handle(signing.Event{
		Type:      signing.EventWaiting,
		At:        time.Now(),
		Operation: signing.OperationAgeDecrypt,
	})
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastSignEvent != "" || loaded.ProviderState != "not_loaded" {
		t.Fatalf("age coordinator event changed SSH state: %+v", loaded)
	}

	now := time.Now().UTC().Truncate(time.Nanosecond)
	store.HandleAge(ageservice.Event{
		At:      now,
		Backend: ageservice.BackendRecovery,
		Result:  ageservice.Result(ageipc.ClassRecoveryFailed),
	})
	loaded, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgeBackend != "recovery" || loaded.AgeResult != "recovery_failed" || !loaded.LastAgeAt.Equal(now) {
		t.Fatalf("age state = %+v", loaded)
	}
}

func TestStoreRejectsUnclassifiedAgeState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore(path)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	store.HandleAge(ageservice.Event{
		At:      time.Now(),
		Backend: ageservice.Backend("op://private/reference"),
		Result:  ageservice.Result("private file key"),
	})
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgeBackend != "" || loaded.AgeResult != "" || !loaded.LastAgeAt.IsZero() {
		t.Fatalf("unclassified age state was persisted: %+v", loaded)
	}
}

func TestStorePersistsAgentRouteSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore(path)
	if err := store.Initialize(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Nanosecond)
	store.SetRoute(agentroute.Snapshot{
		Route:             agentroute.Route1Password,
		ProbeState:        agentroute.ProbeNotDetected,
		FallbackChecked:   true,
		FallbackReachable: true,
		FallbackKeyFound:  true,
		FallbackOtherKeys: 2,
		ChangedAt:         now.Add(-time.Second),
		UpdatedAt:         now,
	})

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgentRoute != string(agentroute.Route1Password) ||
		loaded.RouteProbeState != string(agentroute.ProbeNotDetected) ||
		!loaded.FallbackChecked || !loaded.FallbackReachable || !loaded.FallbackKeyFound || loaded.FallbackOtherKeys != 2 ||
		!loaded.RouteChangedAt.Equal(now.Add(-time.Second)) || !loaded.RouteUpdatedAt.Equal(now) {
		t.Fatalf("route state = %+v", loaded)
	}
}
