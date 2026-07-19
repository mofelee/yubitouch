package diagnostic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
)

const defaultMaxBytes int64 = 1 << 20

type Level uint8

const (
	LevelError Level = iota
	LevelInfo
	LevelDebug
)

type Event string

const (
	EventDaemonStarted    Event = "daemon_started"
	EventDaemonStopped    Event = "daemon_stopped"
	EventDaemonFailed     Event = "daemon_failed"
	EventProxyListening   Event = "proxy_listening"
	EventSignInitializing Event = "sign_initializing"
	EventSignWaiting      Event = "sign_waiting_for_touch"
	EventSignSucceeded    Event = "sign_succeeded"
	EventSignFailed       Event = "sign_failed"
	EventSignTimedOut     Event = "sign_timed_out"
	EventSignCanceled     Event = "sign_canceled"
	EventRoutePIV         Event = "agent_route_piv"
	EventRoute1Password   Event = "agent_route_1password"
	EventRouteFailClosed  Event = "agent_route_piv_fail_closed"
	EventLogReset         Event = "log_size_limit_reached"
)

type FailureClass string

const (
	FailureNone                   FailureClass = ""
	FailureCanceled               FailureClass = "canceled"
	FailureTimeout                FailureClass = "timeout"
	FailureDeviceUnavailable      FailureClass = "device_unavailable"
	FailureKeyMismatch            FailureClass = "key_mismatch"
	FailureProviderInitialization FailureClass = "provider_initialization"
	FailureBackendUnavailable     FailureClass = "backend_unavailable"
	FailurePermission             FailureClass = "permission"
	FailureConfiguration          FailureClass = "configuration"
	FailureInternal               FailureClass = "internal"
)

type record struct {
	Timestamp    string       `json:"timestamp"`
	Level        string       `json:"level"`
	Event        Event        `json:"event"`
	FailureClass FailureClass `json:"failure_class,omitempty"`
}

type Logger struct {
	mu       sync.Mutex
	file     *os.File
	level    Level
	maxBytes int64
	now      func() time.Time
}

func Path(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "yubitouch.log")
}

func Open(path string, configuredLevel string) (*Logger, error) {
	level, err := parseLevel(configuredLevel)
	if err != nil {
		return nil, err
	}
	if err := config.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := openPrivateLog(path)
	if err != nil {
		return nil, err
	}
	return &Logger{
		file:     file,
		level:    level,
		maxBytes: defaultMaxBytes,
		now:      time.Now,
	}, nil
}

func (l *Logger) Write(level Level, event Event, failure FailureClass) error {
	if l == nil {
		return nil
	}
	if !validLevel(level) || !validEvent(event) || !validFailureClass(failure) {
		return errors.New("diagnostic log rejected an unclassified record")
	}
	if level > l.level {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return fs.ErrClosed
	}
	entry, err := l.marshal(level, event, failure)
	if err != nil {
		return err
	}
	info, err := l.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+int64(len(entry)) > l.maxBytes {
		if err := l.file.Truncate(0); err != nil {
			return err
		}
		if _, err := l.file.Seek(0, 0); err != nil {
			return err
		}
		reset, err := l.marshal(LevelInfo, EventLogReset, FailureNone)
		if err != nil {
			return err
		}
		if _, err := l.file.Write(reset); err != nil {
			return err
		}
	}
	_, err = l.file.Write(entry)
	return err
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func (l *Logger) marshal(level Level, event Event, failure FailureClass) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record{
		Timestamp:    l.now().UTC().Format(time.RFC3339Nano),
		Level:        level.String(),
		Event:        event,
		FailureClass: failure,
	}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (l Level) String() string {
	switch l {
	case LevelError:
		return "error"
	case LevelDebug:
		return "debug"
	default:
		return "info"
	}
}

func parseLevel(value string) (Level, error) {
	switch value {
	case "error":
		return LevelError, nil
	case "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	default:
		return LevelError, fmt.Errorf("invalid diagnostic log level %q", value)
	}
}

func validLevel(level Level) bool {
	return level == LevelError || level == LevelInfo || level == LevelDebug
}

func validEvent(event Event) bool {
	switch event {
	case EventDaemonStarted,
		EventDaemonStopped,
		EventDaemonFailed,
		EventProxyListening,
		EventSignInitializing,
		EventSignWaiting,
		EventSignSucceeded,
		EventSignFailed,
		EventSignTimedOut,
		EventSignCanceled,
		EventRoutePIV,
		EventRoute1Password,
		EventRouteFailClosed,
		EventLogReset:
		return true
	default:
		return false
	}
}

func validFailureClass(failure FailureClass) bool {
	switch failure {
	case FailureNone,
		FailureCanceled,
		FailureTimeout,
		FailureDeviceUnavailable,
		FailureKeyMismatch,
		FailureProviderInitialization,
		FailureBackendUnavailable,
		FailurePermission,
		FailureConfiguration,
		FailureInternal:
		return true
	default:
		return false
	}
}

func openPrivateLog(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("diagnostic log must be a regular file, not a symlink: %s", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	closeWithError := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		return closeWithError(err)
	}
	if !opened.Mode().IsRegular() {
		return closeWithError(fmt.Errorf("diagnostic log is not a regular file: %s", path))
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWithError(err)
	}
	return file, nil
}

func Classify(err error) FailureClass {
	if err == nil {
		return FailureNone
	}
	if errors.Is(err, signing.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	if errors.Is(err, signing.ErrCanceled) || errors.Is(err, context.Canceled) {
		return FailureCanceled
	}
	if errors.Is(err, signing.ErrDeviceUnavailable) {
		return FailureDeviceUnavailable
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "configured target key") || strings.Contains(message, "key was not found"):
		return FailureKeyMismatch
	case strings.Contains(message, "device removed") || strings.Contains(message, "device unavailable") || strings.Contains(message, "device not found") || strings.Contains(message, "no yubikey") || strings.Contains(message, "yubikey is unavailable"):
		return FailureDeviceUnavailable
	case strings.Contains(message, "ssh-add") || strings.Contains(message, "pin provider") || strings.Contains(message, "askpass") || strings.Contains(message, "ykcs11"):
		return FailureProviderInitialization
	case strings.Contains(message, "permission") || strings.Contains(message, "operation not permitted"):
		return FailurePermission
	case strings.Contains(message, "config"):
		return FailureConfiguration
	case strings.Contains(message, "ssh-agent") || strings.Contains(message, "socket"):
		return FailureBackendUnavailable
	default:
		return FailureInternal
	}
}

type SigningSink struct {
	logger *Logger
}

func NewSigningSink(logger *Logger) SigningSink {
	return SigningSink{logger: logger}
}

func (s SigningSink) Handle(event signing.Event) {
	if s.logger == nil {
		return
	}
	switch event.Type {
	case signing.EventInitializing:
		_ = s.logger.Write(LevelDebug, EventSignInitializing, FailureNone)
	case signing.EventWaiting:
		_ = s.logger.Write(LevelDebug, EventSignWaiting, FailureNone)
	case signing.EventSuccess:
		_ = s.logger.Write(LevelInfo, EventSignSucceeded, FailureNone)
	case signing.EventTimeout:
		_ = s.logger.Write(LevelError, EventSignTimedOut, FailureTimeout)
	case signing.EventCanceled:
		_ = s.logger.Write(LevelInfo, EventSignCanceled, FailureCanceled)
	case signing.EventFailure:
		_ = s.logger.Write(LevelError, EventSignFailed, Classify(event.Err))
	}
}
