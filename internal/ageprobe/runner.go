package ageprobe

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mofelee/yubitouch/internal/agehardware"
	"github.com/mofelee/yubitouch/internal/parentwatch"
)

type commandFactory func(string) *exec.Cmd

// Runner executes every read-only operation in a fresh, killable process.
// It is safe for concurrent use because it retains no active child state.
type Runner struct {
	executable  string
	configPath  string
	timeout     time.Duration
	environment []string
	command     commandFactory
}

// NewRunner constructs a read-only age hardware process boundary.
func NewRunner(executable, configPath string, timeout time.Duration) *Runner {
	if executable == "" {
		executable, _ = os.Executable()
	}
	return &Runner{
		executable:  executable,
		configPath:  configPath,
		timeout:     timeout,
		environment: append([]string(nil), os.Environ()...),
		command: func(path string) *exec.Cmd {
			return exec.Command(path)
		},
	}
}

// Close implements the same lifecycle shape as the in-process backend. A
// Runner owns no persistent process or PKCS#11 module.
func (r *Runner) Close() error {
	return nil
}

// ReadPublic reads a configured public key without allowing the caller to run
// synchronous PKCS#11 code in its own process.
func (r *Runner) ReadPublic(ctx context.Context, serial, slot string) ([32]byte, error) {
	var publicKey [32]byte
	result, err := r.run(ctx, request{Operation: OperationReadPublic, Serial: serial, Slot: slot})
	if err != nil {
		clear(result.PublicKey[:])
		return publicKey, err
	}
	if result.State != "" {
		clear(result.PublicKey[:])
		return publicKey, classError(ErrorHelper)
	}
	copy(publicKey[:], result.PublicKey[:])
	clear(result.PublicKey[:])
	return publicKey, nil
}

// Probe verifies the serial, slot, and cached public key in a fresh helper.
func (r *Runner) Probe(ctx context.Context, target agehardware.Target) (agehardware.ProbeResult, error) {
	result, err := r.run(ctx, request{
		Operation: OperationProbe,
		Serial:    target.Serial,
		Slot:      target.Slot,
		PublicKey: target.PublicKey,
	})
	clear(result.PublicKey[:])
	if err == nil {
		return agehardware.ProbeResult{State: result.State}, nil
	}
	switch ErrorClassOf(err) {
	case ErrorNotDetected:
		return agehardware.ProbeResult{State: agehardware.NotDetected}, err
	case ErrorTargetMismatch:
		return agehardware.ProbeResult{State: agehardware.Mismatch}, err
	default:
		return agehardware.ProbeResult{State: agehardware.Unavailable}, err
	}
}

func (r *Runner) run(ctx context.Context, value request) (response, error) {
	if r == nil {
		return response{}, classError(ErrorHelper)
	}
	encoded, err := marshalRequest(value)
	if err != nil {
		return response{}, err
	}
	started := false
	defer func() {
		if !started {
			clear(encoded)
		}
	}()

	if ctx == nil {
		ctx = context.Background()
	}
	var callCtx context.Context
	var cancel context.CancelFunc
	if r.timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, r.timeout)
	} else {
		callCtx, cancel = context.WithCancel(ctx)
	}
	if err := callCtx.Err(); err != nil {
		cancel()
		return response{}, classError(contextClass(err))
	}
	if !validExecutable(r.executable) || !validConfigPath(r.configPath) || r.command == nil {
		cancel()
		return response{}, classError(ErrorHelper)
	}

	cmd := r.command(r.executable)
	if cmd == nil {
		cancel()
		return response{}, classError(ErrorHelper)
	}
	cmd.Env = sanitizedEnvironment(r.environment, r.configPath)
	cmd.Stderr = io.Discard
	configureHelperProcess(cmd)
	parentWatch, parentAlive, err := parentwatch.Attach(cmd)
	if err != nil {
		cancel()
		return response{}, classError(ErrorHelper)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		cancel()
		return response{}, classError(ErrorHelper)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		cancel()
		return response{}, classError(ErrorHelper)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		cancel()
		return response{}, classError(ErrorHelper)
	}
	_ = parentWatch.Close()

	call := &helperCall{
		cmd:         cmd,
		ctx:         callCtx,
		cancel:      cancel,
		operation:   value.Operation,
		stdin:       stdin,
		stdout:      stdout,
		parentAlive: parentAlive,
		done:        make(chan struct{}),
	}
	started = true
	go call.exchange(encoded)
	go call.watchContext()
	return call.wait()
}

type helperCall struct {
	cmd       *exec.Cmd
	ctx       context.Context
	cancel    context.CancelFunc
	operation Operation
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	// parentAlive remains open until the helper has been reaped. Kernel closure
	// on launcher death is the helper's lifetime signal.
	parentAlive io.Closer
	done        chan struct{}

	stdinClose  sync.Once
	stdoutClose sync.Once
	mu          sync.Mutex
	result      response
	err         error
}

func (c *helperCall) wait() (response, error) {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.result, c.err
}

func (c *helperCall) watchContext() {
	select {
	case <-c.ctx.Done():
		c.closePipes()
	case <-c.done:
	}
}

func (c *helperCall) exchange(encoded []byte) {
	defer clear(encoded)
	defer c.cancel()

	var encodedResponse []byte
	protocolOK := true
	if err := writeFrame(c.stdin, encoded, maxRequestFrame); err != nil {
		protocolOK = false
	}
	if err := c.closeStdin(); err != nil {
		protocolOK = false
	}
	if protocolOK {
		var err error
		encodedResponse, err = readFrame(c.stdout, maxResponseFrame)
		if err != nil {
			protocolOK = false
		}
	}
	if protocolOK && ensureEOF(c.stdout) != nil {
		protocolOK = false
	}
	_ = c.closeStdout()
	killHelperProcessGroup(c.cmd)
	waitErr := c.cmd.Wait()
	_ = c.parentAlive.Close()

	var result response
	var resultErr error
	if contextErr := c.ctx.Err(); contextErr != nil {
		resultErr = classError(contextClass(contextErr))
	} else if !protocolOK {
		resultErr = classError(ErrorHelper)
	} else {
		result, resultErr = unmarshalResponse(encodedResponse, c.operation)
		if resultErr == nil && waitErr != nil {
			clear(result.PublicKey[:])
			result = response{}
			resultErr = classError(ErrorHelper)
		}
	}
	clear(encodedResponse)

	c.mu.Lock()
	c.result = result
	c.err = resultErr
	c.mu.Unlock()
	close(c.done)
}

func (c *helperCall) closeStdin() (err error) {
	c.stdinClose.Do(func() { err = c.stdin.Close() })
	return err
}

func (c *helperCall) closeStdout() (err error) {
	c.stdoutClose.Do(func() { err = c.stdout.Close() })
	return err
}

func (c *helperCall) closePipes() {
	_ = c.closeStdin()
	_ = c.closeStdout()
}

// killHelperProcessGroup runs immediately before the sole Cmd.Wait call, so a
// reaped PID cannot be reused between wait and signal.
func killHelperProcessGroup(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
		return true
	}
	return cmd.Process.Kill() == nil
}

func configureHelperProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func sanitizedEnvironment(base []string, configPath string) []string {
	allowed := make([]string, 0, len(base)+3)
	seen := make(map[string]bool)
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || seen[name] || !allowedEnvironmentName(name) {
			continue
		}
		seen[name] = true
		allowed = append(allowed, entry)
	}
	return append(allowed,
		internalModeEnvironment+"=1",
		"YUBITOUCH_CONFIG="+configPath,
		parentwatch.Environment(parentWatchEnvironment),
	)
}

func allowedEnvironmentName(name string) bool {
	switch name {
	case "HOME", "USER", "LOGNAME", "PATH", "SHELL", "TMPDIR", "LANG", "LANGUAGE", "TZ", "__CF_USER_TEXT_ENCODING", "XPC_FLAGS", "XPC_SERVICE_NAME":
		return true
	default:
		return strings.HasPrefix(name, "LC_")
	}
}

func validExecutable(path string) bool {
	return path != "" && filepath.IsAbs(path) && !strings.ContainsRune(path, 0)
}

func validConfigPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && !strings.ContainsRune(path, 0)
}
