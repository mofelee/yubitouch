package command

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mofelee/yubitouch/internal/buildinfo"
	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/internal/daemon"
	"github.com/mofelee/yubitouch/internal/launchagent"
	"github.com/mofelee/yubitouch/internal/state"
	"github.com/mofelee/yubitouch/internal/system"
	"github.com/mofelee/yubitouch/native/macos"
	"golang.org/x/crypto/ssh/agent"
)

const (
	ExitOK            = 0
	ExitRuntimeError  = 1
	ExitConfigError   = 2
	ExitDeviceMissing = 3
	ExitPINFailure    = 4
	ExitKeyMismatch   = 5
	ExitSignTimeout   = 6
)

type Environment struct {
	Home   string
	Getenv func(string) string
}

func OS() Environment {
	home, _ := os.UserHomeDir()
	return Environment{Home: home, Getenv: os.Getenv}
}

func Run(args []string, stdout io.Writer, stderr io.Writer, env Environment) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if env.Home == "" {
		fmt.Fprintln(stderr, "yubitouch: cannot determine the user home directory")
		return ExitConfigError
	}
	if len(args) == 0 {
		printUsage(stderr)
		return ExitConfigError
	}

	switch args[0] {
	case "configure":
		return runConfigure(stdout, stderr, env)
	case "ensure":
		return runEnsure(stdout, stderr, env)
	case "reload":
		return runReload(stdout, stderr, env)
	case "stop":
		return runStop(stdout, stderr)
	case "test-sign":
		return runTestSign(stdout, stderr, env)
	case "about":
		return runAbout()
	case "daemon":
		return runDaemon(args[1:], stderr, env)
	case "status":
		jsonOutput := len(args) == 2 && args[1] == "--json"
		if len(args) > 1 && !jsonOutput {
			fmt.Fprintln(stderr, "usage: yubitouch status [--json]")
			return ExitConfigError
		}
		return runStatus(stdout, stderr, env, jsonOutput)
	case "doctor":
		return runDoctor(stdout, stderr, env)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "yubitouch %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return ExitOK
	case "help", "--help", "-h":
		printUsage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "yubitouch: unknown command %q\n", args[0])
		printUsage(stderr)
		return ExitConfigError
	}
}

type Status struct {
	Version           string `json:"version"`
	ConfigPath        string `json:"config_path"`
	Configured        bool   `json:"configured"`
	ConfigPermissions string `json:"config_permissions,omitempty"`
	AgentSocket       string `json:"agent_socket,omitempty"`
	AgentReachable    bool   `json:"agent_reachable"`
	BackendSocket     string `json:"backend_socket,omitempty"`
	BackendReachable  bool   `json:"backend_reachable"`
	PINProvider       string `json:"pin_provider,omitempty"`
	PublicKey         string `json:"public_key,omitempty"`
	ProviderState     string `json:"provider_state"`
	LaunchAgentLoaded bool   `json:"launch_agent_loaded"`
	DaemonPID         int    `json:"daemon_pid,omitempty"`
	LastSignEvent     string `json:"last_sign_event,omitempty"`
	LastSignAt        string `json:"last_sign_at,omitempty"`
}

func runConfigure(stdout io.Writer, stderr io.Writer, env Environment) int {
	path := config.PathFromEnvironment(env.Home, env.Getenv)
	cfg, err := config.LoadForConfigure(path, env.Home, env.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return ExitConfigError
	}
	if err := config.Save(path, cfg); err != nil {
		fmt.Fprintf(stderr, "cannot save configuration: %v\n", err)
		return ExitRuntimeError
	}
	fmt.Fprintf(stdout, "Configuration saved to %s\n", path)
	fmt.Fprintf(stdout, "Public key: %s\n", cfg.Fingerprint())
	fmt.Fprintln(stdout, "No PIN was read and no provider was loaded.")
	return ExitOK
}

func runStatus(stdout io.Writer, stderr io.Writer, env Environment, jsonOutput bool) int {
	path := config.PathFromEnvironment(env.Home, env.Getenv)
	status := Status{
		Version:       buildinfo.Version,
		ConfigPath:    path,
		ProviderState: "not_loaded",
	}
	if info, err := os.Lstat(path); err == nil {
		status.Configured = true
		status.ConfigPermissions = fmt.Sprintf("%04o", info.Mode().Perm())
	}

	cfg, err := config.Load(path, env.Home)
	if err != nil {
		if jsonOutput {
			_ = writeJSON(stdout, status)
		}
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(stderr, "not configured: run yubitouch configure (%s)\n", path)
		} else {
			fmt.Fprintf(stderr, "configuration error: %v\n", err)
		}
		return ExitConfigError
	}
	status.AgentSocket = cfg.SocketPath
	status.LaunchAgentLoaded = launchAgentLoaded()
	status.AgentReachable = socketReachable(cfg.SocketPath)
	status.BackendSocket = cfg.BackendSocketPath
	status.BackendReachable = socketReachable(cfg.BackendSocketPath)
	status.PINProvider = string(cfg.PINProvider)
	status.PublicKey = cfg.Fingerprint()
	if status.BackendReachable {
		status.ProviderState = "unknown"
	}
	if persisted, err := state.Load(filepath.Join(filepath.Dir(path), "state.json")); err == nil {
		status.DaemonPID = persisted.PID
		status.ProviderState = persisted.ProviderState
		status.LastSignEvent = persisted.LastSignEvent
		if !persisted.LastSignAt.IsZero() {
			status.LastSignAt = persisted.LastSignAt.Format(time.RFC3339)
		}
	}

	if jsonOutput {
		if err := writeJSON(stdout, status); err != nil {
			fmt.Fprintf(stderr, "write status: %v\n", err)
			return ExitRuntimeError
		}
		return ExitOK
	}
	fmt.Fprintf(stdout, "Config: %s (%s)\n", status.ConfigPath, status.ConfigPermissions)
	fmt.Fprintf(stdout, "Agent socket: %s\n", availability(status.AgentReachable))
	fmt.Fprintf(stdout, "LaunchAgent: %s\n", availability(status.LaunchAgentLoaded))
	fmt.Fprintf(stdout, "Backend socket: %s\n", availability(status.BackendReachable))
	fmt.Fprintf(stdout, "Provider: %s\n", status.ProviderState)
	fmt.Fprintf(stdout, "PIN provider: %s\n", status.PINProvider)
	fmt.Fprintf(stdout, "Public key: %s\n", status.PublicKey)
	return ExitOK
}

func runDoctor(stdout io.Writer, stderr io.Writer, env Environment) int {
	path := config.PathFromEnvironment(env.Home, env.Getenv)
	cfg, err := config.Load(path, env.Home)
	if err != nil {
		fmt.Fprintf(stderr, "[FAIL] configuration: %v\n", err)
		return ExitConfigError
	}

	failed := false
	check := func(ok bool, name string, detail string) {
		if ok {
			fmt.Fprintf(stdout, "[OK] %s: %s\n", name, detail)
			return
		}
		failed = true
		fmt.Fprintf(stdout, "[FAIL] %s: %s\n", name, detail)
	}

	info, statErr := os.Lstat(path)
	check(statErr == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600,
		"configuration permissions", "expected a regular 0600 file at "+path)
	runtimeDir := filepath.Dir(path)
	dirInfo, dirErr := os.Lstat(runtimeDir)
	check(dirErr == nil && dirInfo.IsDir() && dirInfo.Mode().Perm() == 0o700,
		"runtime directory permissions", "expected 0700 at "+runtimeDir)
	check(cfg.PublicKey != nil, "target public key", cfg.Fingerprint())
	check(launchAgentLoaded(), "LaunchAgent", launchagent.Label)

	deps, depErr := system.Resolve(cfg)
	if depErr != nil {
		check(false, "OpenSSH/YKCS11 dependencies", depErr.Error())
	} else {
		check(true, "ssh-agent", deps.SSHAgent)
		check(true, "ssh-add", deps.SSHAdd)
		check(true, "ssh-keygen", deps.SSHKeygen)
		check(true, "YKCS11", deps.YKCS11)
		hardwareCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		report, hardwareErr := system.InspectHardware(hardwareCtx, cfg, deps)
		cancel()
		if hardwareErr != nil {
			check(false, "YubiKey PIV", hardwareErr.Error())
		} else {
			check(report.DeviceCount > 0, "YubiKey", fmt.Sprintf("%d device(s) detected", report.DeviceCount))
			check(report.SlotAlgorithm == "ED25519", "PIV 9A algorithm", report.SlotAlgorithm)
			check(report.TouchPolicy == "ALWAYS", "PIV 9A touch policy", report.TouchPolicy)
			check(report.TargetKeyFound, "configured key in YKCS11", cfg.Fingerprint())
			check(true, "hidden provider keys", fmt.Sprintf("%d non-target key(s) will be filtered", report.OtherProviderKeys))
		}
	}
	check(socketReachable(cfg.SocketPath), "public agent socket", cfg.SocketPath)
	sshReport, sshErr := system.InspectSSHConfig(
		filepath.Join(env.Home, ".ssh", "config"),
		env.Home,
		cfg.SocketPath,
		cfg.BackendSocketPath,
	)
	if sshErr != nil {
		check(false, "SSH config", sshErr.Error())
	} else {
		check(sshReport.Exists, "SSH config", filepath.Join(env.Home, ".ssh", "config"))
		check(sshReport.UsesPublicAgent, "SSH IdentityAgent", cfg.SocketPath)
		check(!sshReport.UsesBackend, "backend socket isolation", "backend socket is not referenced by SSH config")
		check(!sshReport.HasMatchExec, "side-effect-free SSH config", "no YubiTouch Match exec directive")
	}
	if cfg.PINProvider == config.PINProvider1Password {
		check(strings.TrimSpace(cfg.OnePasswordAccount) != "", "1Password account", "configured")
		check(strings.HasPrefix(cfg.OnePasswordRef, "op://"), "1Password reference", "configured and redacted")
	}

	if failed {
		return ExitRuntimeError
	}
	return ExitOK
}

func runEnsure(stdout io.Writer, stderr io.Writer, env Environment) int {
	path := config.PathFromEnvironment(env.Home, env.Getenv)
	cfg, err := config.Load(path, env.Home)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return ExitConfigError
	}
	executable, err := resolvedExecutable()
	if err != nil {
		fmt.Fprintf(stderr, "cannot resolve executable: %v\n", err)
		return ExitRuntimeError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := launchagent.Ensure(ctx, env.Home, executable, path); err != nil {
		fmt.Fprintf(stderr, "cannot ensure LaunchAgent: %v\n", err)
		return ExitRuntimeError
	}
	if err := launchagent.WaitForSocket(ctx, cfg.SocketPath); err != nil {
		fmt.Fprintf(stderr, "LaunchAgent started but agent socket is unavailable: %v\n", err)
		return ExitRuntimeError
	}
	fmt.Fprintln(stdout, "YubiTouch LaunchAgent and public agent socket are ready.")
	fmt.Fprintln(stdout, "No PIN was read and no provider was loaded.")
	return ExitOK
}

func runReload(stdout io.Writer, stderr io.Writer, env Environment) int {
	path := config.PathFromEnvironment(env.Home, env.Getenv)
	cfg, err := config.Load(path, env.Home)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return ExitConfigError
	}
	executable, err := resolvedExecutable()
	if err != nil {
		fmt.Fprintf(stderr, "cannot resolve executable: %v\n", err)
		return ExitRuntimeError
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := launchagent.Reload(ctx, env.Home, executable, path); err != nil {
		fmt.Fprintf(stderr, "cannot reload LaunchAgent: %v\n", err)
		return ExitRuntimeError
	}
	if err := launchagent.WaitForSocket(ctx, cfg.SocketPath); err != nil {
		fmt.Fprintf(stderr, "LaunchAgent reloaded but agent socket is unavailable: %v\n", err)
		return ExitRuntimeError
	}
	fmt.Fprintln(stdout, "YubiTouch reloaded. The provider remains lazy until a sign request.")
	return ExitOK
}

func runStop(stdout io.Writer, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := launchagent.Stop(ctx); err != nil {
		fmt.Fprintf(stderr, "cannot stop LaunchAgent: %v\n", err)
		return ExitRuntimeError
	}
	fmt.Fprintln(stdout, "YubiTouch stopped.")
	return ExitOK
}

func runTestSign(stdout io.Writer, stderr io.Writer, env Environment) int {
	path := config.PathFromEnvironment(env.Home, env.Getenv)
	cfg, err := config.Load(path, env.Home)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return ExitConfigError
	}
	conn, err := net.DialTimeout("unix", cfg.SocketPath, time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "public agent socket is unavailable: %v\n", err)
		return ExitRuntimeError
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.SignTimeout.Duration + time.Second))
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		fmt.Fprintf(stderr, "cannot list YubiTouch identities: %v\n", err)
		return ExitRuntimeError
	}
	if len(keys) != 1 || !bytes.Equal(keys[0].Blob, cfg.PublicKey.Marshal()) {
		fmt.Fprintln(stderr, "YubiTouch did not expose exactly the configured target key")
		return ExitKeyMismatch
	}
	payload := make([]byte, 32)
	if _, err := rand.Read(payload); err != nil {
		fmt.Fprintln(stderr, "cannot create the local test request")
		return ExitRuntimeError
	}
	defer zeroBytes(payload)
	if _, err := client.Sign(cfg.PublicKey, payload); err != nil {
		var netErr net.Error
		if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			fmt.Fprintln(stderr, "test signature timed out")
			return ExitSignTimeout
		}
		fmt.Fprintf(stderr, "test signature failed: %v\n", err)
		return ExitRuntimeError
	}
	fmt.Fprintln(stdout, "Test signature succeeded. Signature data was not retained.")
	return ExitOK
}

func runAbout() int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	macos.ShowAbout()
	return ExitOK
}

func launchAgentLoaded() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	return launchagent.IsLoaded(ctx)
}

func runDaemon(args []string, stderr io.Writer, env Environment) int {
	if len(args) != 2 || args[0] != "--config" || strings.TrimSpace(args[1]) == "" {
		fmt.Fprintln(stderr, "internal daemon usage: yubitouch daemon --config <path>")
		return ExitConfigError
	}
	options, err := daemon.OptionsFromOS(filepath.Clean(args[1]), env.Home)
	if err != nil {
		fmt.Fprintf(stderr, "daemon setup failed: %v\n", err)
		return ExitRuntimeError
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := daemon.Run(ctx, options); err != nil {
		fmt.Fprintf(stderr, "daemon failed: %v\n", err)
		return ExitRuntimeError
	}
	return ExitOK
}

func resolvedExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func socketReachable(path string) bool {
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func availability(ok bool) string {
	if ok {
		return "reachable"
	}
	return "unavailable"
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: yubitouch <command>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  configure       Validate and persist non-secret configuration")
	fmt.Fprintln(w, "  ensure          Ensure the LaunchAgent and public socket are ready")
	fmt.Fprintln(w, "  status [--json] Show configuration and service state")
	fmt.Fprintln(w, "  reload          Reload non-secret configuration")
	fmt.Fprintln(w, "  stop            Stop the current-user LaunchAgent")
	fmt.Fprintln(w, "  doctor          Check local dependencies and permissions")
	fmt.Fprintln(w, "  test-sign       Exercise the local PIN, touch, and sign flow")
	fmt.Fprintln(w, "  about           Show project identity and affiliation information")
	fmt.Fprintln(w, "  version         Show version information")
}
