package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mofelee/yubitouch/internal/agentproxy"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/signing"
	"github.com/mofelee/yubitouch/internal/system"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const backendStartTimeout = 3 * time.Second
const deviceProbeTimeout = 3 * time.Second
const deviceProbeInterval = 100 * time.Millisecond

type Manager struct {
	cfg        config.Config
	deps       system.Dependencies
	executable string
	configPath string
	processEnv []string
	probeKeys  func(context.Context) (int, error)

	mu       sync.Mutex
	cmd      *exec.Cmd
	waitDone chan error

	providerMu sync.Mutex
	invalid    bool
}

func New(cfg config.Config, deps system.Dependencies, executable string, configPath string) *Manager {
	return &Manager{
		cfg:        cfg,
		deps:       deps,
		executable: executable,
		configPath: configPath,
		processEnv: sanitizedEnvironment(os.Environ()),
		probeKeys:  system.ProbeYubiKeys,
	}
}

func (m *Manager) SetDeviceProbe(probe func(context.Context) (int, error)) {
	if probe != nil {
		m.probeKeys = probe
	}
}

func (m *Manager) Connect(ctx context.Context) (agentproxy.Backend, error) {
	if err := m.EnsureAgent(ctx); err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", m.cfg.BackendSocketPath)
	if err != nil {
		return nil, err
	}
	return &client{ExtendedAgent: agent.NewClient(conn), conn: conn}, nil
}

func (m *Manager) EnsureAgent(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		if socketReachable(m.cfg.BackendSocketPath) {
			return nil
		}
		if err := m.discardUnavailableAgentLocked(ctx); err != nil {
			return err
		}
	}
	if err := prepareSocketPath(m.cfg.BackendSocketPath); err != nil {
		return err
	}

	cmd := exec.Command(m.deps.SSHAgent, m.agentArguments()...)
	cmd.Env = m.processEnv
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	m.cmd = cmd
	m.waitDone = make(chan error, 1)
	go func(done chan<- error) { done <- cmd.Wait() }(m.waitDone)

	deadline := time.NewTimer(backendStartTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if socketReachable(m.cfg.BackendSocketPath) {
			if err := os.Chmod(m.cfg.BackendSocketPath, 0o600); err != nil {
				_ = cmd.Process.Kill()
				return err
			}
			return nil
		}
		select {
		case err := <-m.waitDone:
			m.cmd = nil
			m.waitDone = nil
			return fmt.Errorf("ssh-agent failed to start: %w: %s", err, strings.TrimSpace(stderr.String()))
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return ctx.Err()
		case <-deadline.C:
			_ = cmd.Process.Kill()
			return errors.New("timed out waiting for the backend ssh-agent socket")
		case <-ticker.C:
		}
	}
}

func (m *Manager) agentArguments() []string {
	args := []string{"-D", "-a", m.cfg.BackendSocketPath}
	if strings.TrimSpace(m.deps.YKCS11) != "" {
		args = append(args, "-P", m.deps.YKCS11)
	}
	return args
}

func (m *Manager) discardUnavailableAgentLocked(ctx context.Context) error {
	if m.cmd == nil {
		return nil
	}
	select {
	case <-m.waitDone:
		m.cmd = nil
		m.waitDone = nil
		return nil
	default:
	}
	if m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	select {
	case <-m.waitDone:
		m.cmd = nil
		m.waitDone = nil
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Ensure(ctx context.Context) error {
	m.providerMu.Lock()
	defer m.providerMu.Unlock()

	if m.invalid {
		_ = m.unloadProvider(ctx)
		m.invalid = false
	}
	loaded, err := m.targetLoaded(ctx)
	if err != nil {
		return err
	}
	if loaded {
		return nil
	}
	if err := m.loadProvider(ctx); err != nil {
		return err
	}
	loaded, err = m.targetLoaded(ctx)
	if err != nil {
		return err
	}
	if !loaded {
		return errors.New("YKCS11 loaded, but the configured target key was not found")
	}
	return nil
}

func (m *Manager) Invalidate() {
	m.providerMu.Lock()
	m.invalid = true
	m.providerMu.Unlock()
}

func (m *Manager) NormalizeSignFailure(ctx context.Context, signErr error) error {
	probeCtx, cancel := context.WithTimeout(ctx, deviceProbeTimeout)
	defer cancel()
	ticker := time.NewTicker(deviceProbeInterval)
	defer ticker.Stop()
	for {
		count, err := m.probeKeys(probeCtx)
		if err == nil && count == 0 {
			return fmt.Errorf("%w: %v", signing.ErrDeviceUnavailable, signErr)
		}
		select {
		case <-probeCtx.Done():
			return signErr
		case <-ticker.C:
		}
	}
}

func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	_ = m.cmd.Process.Signal(os.Interrupt)
	select {
	case <-m.waitDone:
	case <-ctx.Done():
		_ = m.cmd.Process.Kill()
		<-m.waitDone
	}
	m.cmd = nil
	m.waitDone = nil
	_ = os.Remove(m.cfg.BackendSocketPath)
	return nil
}

func (m *Manager) targetLoaded(ctx context.Context) (bool, error) {
	backend, err := m.Connect(ctx)
	if err != nil {
		return false, err
	}
	defer backend.Close()
	keys, err := backend.List()
	if err != nil {
		return false, err
	}
	for _, key := range keys {
		parsed, err := ssh.ParsePublicKey(key.Blob)
		if err == nil && bytes.Equal(parsed.Marshal(), m.cfg.PublicKey.Marshal()) {
			return true, nil
		}
	}
	return false, nil
}

func (m *Manager) loadProvider(ctx context.Context) error {
	provider, err := system.ResolveYKCS11(m.cfg.YKCS11Path)
	if err != nil {
		return err
	}
	guard, err := newGuardPath(filepath.Dir(m.configPath))
	if err != nil {
		return err
	}
	defer os.Remove(guard)

	cmd := exec.CommandContext(ctx, m.deps.SSHAdd, "-s", provider)
	configureProcessGroupCancellation(cmd)
	cmd.Env = append(append([]string{}, m.processEnv...),
		"SSH_AUTH_SOCK="+m.cfg.BackendSocketPath,
		"SSH_ASKPASS_REQUIRE=force",
		"SSH_ASKPASS="+m.executable,
		"DISPLAY=yubitouch",
		"YUBITOUCH_INTERNAL_ASKPASS=1",
		"YUBITOUCH_ASKPASS_GUARD="+guard,
		"YUBITOUCH_CONFIG="+m.configPath,
	)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-add could not load YKCS11: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	m.deps.YKCS11 = provider
	return nil
}

func configureProcessGroupCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func (m *Manager) unloadProvider(ctx context.Context) error {
	if err := m.EnsureAgent(ctx); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, m.deps.SSHAdd, "-e", m.deps.YKCS11)
	cmd.Env = append(append([]string{}, m.processEnv...), "SSH_AUTH_SOCK="+m.cfg.BackendSocketPath)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func newGuardPath(dir string) (string, error) {
	file, err := os.CreateTemp(dir, ".askpass-guard-")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func prepareSocketPath(path string) error {
	if err := config.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket backend path: %s", path)
	}
	if socketReachable(path) {
		return fmt.Errorf("an unmanaged agent is already listening at %s", path)
	}
	return os.Remove(path)
}

func socketReachable(path string) bool {
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func sanitizedEnvironment(environment []string) []string {
	blocked := map[string]bool{
		"SSH_AUTH_SOCK":              true,
		"SSH_AGENT_PID":              true,
		"SSH_ASKPASS":                true,
		"SSH_ASKPASS_REQUIRE":        true,
		"YUBITOUCH_INTERNAL_ASKPASS": true,
		"YUBITOUCH_ASKPASS_GUARD":    true,
		"YUBITOUCH_CONFIG":           true,
		"YUBITOUCH_PIN":              true,
		"DISPLAY":                    true,
	}
	result := make([]string, 0, len(environment))
	for _, item := range environment {
		name, _, _ := strings.Cut(item, "=")
		if !blocked[name] {
			result = append(result, item)
		}
	}
	return result
}

type client struct {
	agent.ExtendedAgent
	conn io.Closer
}

func (c *client) Close() error {
	return c.conn.Close()
}
