package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mofelee/yubitouch/internal/agentroute"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/diagnostic"
	"github.com/mofelee/yubitouch/internal/signing"
)

type State struct {
	PID               int       `json:"pid"`
	StartedAt         time.Time `json:"started_at"`
	ProviderState     string    `json:"provider_state"`
	LastSignEvent     string    `json:"last_sign_event,omitempty"`
	LastSignAt        time.Time `json:"last_sign_at,omitempty"`
	LastFailureClass  string    `json:"last_failure_class,omitempty"`
	AgentRoute        string    `json:"agent_route,omitempty"`
	RouteProbeState   string    `json:"route_probe_state,omitempty"`
	RouteChangedAt    time.Time `json:"route_changed_at,omitempty"`
	RouteUpdatedAt    time.Time `json:"route_updated_at,omitempty"`
	FallbackChecked   bool      `json:"fallback_checked"`
	FallbackReachable bool      `json:"fallback_agent_reachable"`
	FallbackKeyFound  bool      `json:"fallback_key_available"`
	FallbackOtherKeys int       `json:"fallback_other_keys"`
}

func (s *Store) SetRoute(snapshot agentroute.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.AgentRoute = string(snapshot.Route)
	s.data.RouteProbeState = string(snapshot.ProbeState)
	s.data.RouteChangedAt = snapshot.ChangedAt
	s.data.RouteUpdatedAt = snapshot.UpdatedAt
	s.data.FallbackChecked = snapshot.FallbackChecked
	s.data.FallbackReachable = snapshot.FallbackReachable
	s.data.FallbackKeyFound = snapshot.FallbackKeyFound
	s.data.FallbackOtherKeys = snapshot.FallbackOtherKeys
	_ = s.writeLocked()
}

type Store struct {
	path string
	mu   sync.Mutex
	data State
}

func NewStore(path string) *Store {
	return &Store{
		path: path,
		data: State{
			PID:           os.Getpid(),
			StartedAt:     time.Now().UTC(),
			ProviderState: "not_loaded",
		},
	}
}

func (s *Store) Initialize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked()
}

func (s *Store) Handle(event signing.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.LastSignEvent = string(event.Type)
	s.data.LastSignAt = event.At.UTC()
	s.data.LastFailureClass = ""
	switch event.Type {
	case signing.EventInitializing:
		s.data.ProviderState = "initializing"
	case signing.EventWaiting, signing.EventSuccess:
		s.data.ProviderState = "loaded"
	case signing.EventFailure, signing.EventCanceled:
		s.data.ProviderState = "unavailable"
		failure := diagnostic.Classify(event.Err)
		if event.Type == signing.EventCanceled {
			failure = diagnostic.FailureCanceled
		}
		if failure == diagnostic.FailureNone {
			failure = diagnostic.FailureInternal
		}
		s.data.LastFailureClass = string(failure)
	case signing.EventTimeout:
		s.data.ProviderState = "unavailable"
		s.data.LastFailureClass = string(diagnostic.FailureTimeout)
	}
	_ = s.writeLocked()
}

func (s *Store) Remove() error {
	err := os.Remove(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func Load(path string) (State, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return State{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return State{}, errors.New("state file must be a regular 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var value State
	if err := json.Unmarshal(data, &value); err != nil {
		return State{}, err
	}
	return value, nil
}

func (s *Store) writeLocked() error {
	if err := config.EnsurePrivateDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}
