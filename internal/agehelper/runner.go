package agehelper

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

	"github.com/mofelee/yubitouch/internal/parentwatch"
)

type commandFactory func(string) *exec.Cmd

// Runner launches one isolated helper process. A Runner is intentionally
// scoped to one daemon request so CancelCurrent can be passed directly to the
// signing coordinator without cross-request process selection.
type Runner struct {
	executable  string
	configPath  string
	timeout     time.Duration
	environment []string
	command     commandFactory

	mu          sync.Mutex
	active      *Call
	preCanceled bool
}

// NewRunner constructs a one-request runner. executable should be the current
// yubitouch executable, not the age plugin executable.
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

// Run starts and waits for one helper. It is the preferred API inside the
// coordinator call closure.
func (r *Runner) Run(ctx context.Context, mode Mode, request Request) ([]byte, error) {
	call, err := r.Start(ctx, mode, request)
	if err != nil {
		return nil, err
	}
	return call.Wait()
}

// Start launches one helper and returns immediately after the child is
// registered for cancellation. The caller must call Wait or Cancel.
func (r *Runner) Start(ctx context.Context, mode Mode, request Request) (*Call, error) {
	if r == nil || !validMode(mode) {
		return nil, classError(ErrorInvalidRequest)
	}
	encoded, err := marshalRequest(request, mode)
	if err != nil {
		return nil, err
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

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.preCanceled || callCtx.Err() != nil {
		cancel()
		return nil, classError(contextClass(callCtx.Err()))
	}
	if r.active != nil {
		cancel()
		return nil, classError(ErrorHelper)
	}
	if !validExecutable(r.executable) || !validConfigPath(r.configPath) || r.command == nil {
		cancel()
		return nil, classError(ErrorHelper)
	}

	cmd := r.command(r.executable)
	if cmd == nil {
		cancel()
		return nil, classError(ErrorHelper)
	}
	cmd.Env = sanitizedEnvironment(r.environment, r.configPath, mode)
	cmd.Stderr = io.Discard
	configureHelperProcess(cmd)
	parentWatch, parentAlive, err := parentwatch.Attach(cmd)
	if err != nil {
		cancel()
		return nil, classError(ErrorHelper)
	}
	var continueChild, continueParent *os.File
	if mode == ModeHardware {
		continueChild, continueParent, err = attachHardwareContinue(cmd)
		if err != nil {
			_ = parentWatch.Close()
			_ = parentAlive.Close()
			cancel()
			return nil, classError(ErrorHelper)
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = closeFile(continueChild)
		_ = closeFile(continueParent)
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		cancel()
		return nil, classError(ErrorHelper)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		_ = closeFile(continueChild)
		_ = closeFile(continueParent)
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		cancel()
		return nil, classError(ErrorHelper)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = closeFile(continueChild)
		_ = closeFile(continueParent)
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		cancel()
		return nil, classError(ErrorHelper)
	}
	_ = parentWatch.Close()
	_ = closeFile(continueChild)

	call := &Call{
		mode:           mode,
		cmd:            cmd,
		ctx:            callCtx,
		cancel:         cancel,
		stdin:          stdin,
		stdout:         stdout,
		continueWriter: continueParent,
		parentAlive:    parentAlive,
		readyDone:      make(chan struct{}),
		done:           make(chan struct{}),
		onDone:         r.finish,
	}
	r.active = call
	started = true
	go call.exchange(encoded)
	go call.watchContext()
	return call, nil
}

// CancelCurrent records cancellation even if it races with Start, kills the
// whole active process group, and waits for the child to be reaped.
func (r *Runner) CancelCurrent() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.preCanceled = true
	call := r.active
	r.mu.Unlock()
	if call != nil {
		call.Cancel()
	}
}

func (r *Runner) finish(call *Call) {
	r.mu.Lock()
	if r.active == call {
		r.active = nil
	}
	r.mu.Unlock()
}

// Call is one started helper subprocess.
type Call struct {
	mode           Mode
	cmd            *exec.Cmd
	ctx            context.Context
	cancel         context.CancelFunc
	stdin          io.WriteCloser
	stdout         io.ReadCloser
	continueWriter io.WriteCloser
	// parentAlive is intentionally kept open until the helper has been reaped.
	// Kernel closure on launcher death is the child's unforgeable death signal.
	parentAlive io.Closer
	readyDone   chan struct{}
	done        chan struct{}
	onDone      func(*Call)

	stdinClose       sync.Once
	stdoutClose      sync.Once
	continueClose    sync.Once
	continueSend     sync.Once
	readyOnce        sync.Once
	continueCloseErr error
	continueSendErr  error
	mu               sync.Mutex
	readyErr         error
	fileKey          []byte
	err              error
}

// Wait preserves the original one-shot API. Hardware calls automatically wait
// for readiness and release the helper; recovery calls remain single-stage.
func (c *Call) Wait() ([]byte, error) {
	if c != nil && c.mode == ModeHardware {
		if err := c.WaitReady(); err != nil {
			return nil, err
		}
		return c.ContinueAndWait()
	}
	return c.waitResult()
}

// WaitReady waits until a hardware helper has resolved its PIN, authenticated
// the target, and blocked on the private continue pipe before key derivation.
// Early terminal failures are returned only after the helper is fully reaped.
func (c *Call) WaitReady() error {
	if c == nil || c.mode != ModeHardware || c.readyDone == nil {
		return classError(ErrorHelper)
	}
	<-c.readyDone
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readyErr
}

// ContinueAndWait releases a ready hardware helper exactly once and waits for
// its terminal response and process exit.
func (c *Call) ContinueAndWait() ([]byte, error) {
	if c == nil || c.mode != ModeHardware {
		return nil, classError(ErrorHelper)
	}
	if err := c.WaitReady(); err != nil {
		return nil, err
	}
	c.continueSend.Do(func() {
		if c.continueWriter == nil {
			c.continueSendErr = classError(ErrorHelper)
			return
		}
		if err := writeHardwareContinue(c.continueWriter); err != nil {
			c.continueSendErr = classError(ErrorHelper)
		}
		if err := c.closeContinue(); err != nil && c.continueSendErr == nil {
			c.continueSendErr = classError(ErrorHelper)
		}
	})
	if c.continueSendErr != nil {
		c.closePipes()
	}
	fileKey, err := c.waitResult()
	if c.continueSendErr != nil && err == nil {
		secureClear(fileKey)
		return nil, c.continueSendErr
	}
	return fileKey, err
}

func (c *Call) waitResult() ([]byte, error) {
	if c == nil || c.done == nil {
		return nil, classError(ErrorHelper)
	}
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fileKey, c.err
}

// Cancel closes the private pipes to wake the exchange goroutine and does not
// return until that goroutine has killed the process group and waited on it.
func (c *Call) Cancel() {
	if c == nil || c.done == nil {
		return
	}
	c.cancel()
	c.closePipes()
	<-c.done
}

func (c *Call) watchContext() {
	select {
	case <-c.ctx.Done():
		c.closePipes()
	case <-c.done:
	}
}

func (c *Call) exchange(encoded []byte) {
	defer clear(encoded)
	defer c.cancel()

	var response []byte
	protocolOK := true
	readyReceived := false
	if err := writeFrame(c.stdin, encoded, maxRequestFrame); err != nil {
		protocolOK = false
	}
	if err := c.closeStdin(); err != nil {
		protocolOK = false
	}
	if protocolOK {
		first, err := readFrame(c.stdout, maxResponseFrame)
		if err != nil {
			protocolOK = false
		} else if c.mode == ModeHardware && unmarshalReady(first) == nil {
			readyReceived = true
			clear(first)
			c.setReady(nil)
			response, err = readFrame(c.stdout, maxResponseFrame)
			if err != nil {
				protocolOK = false
			}
		} else {
			response = first
		}
	}
	if protocolOK && ensureEOF(c.stdout) != nil {
		protocolOK = false
	}
	c.closePipes()
	killHelperProcessGroup(c.cmd)
	waitErr := c.cmd.Wait()
	_ = c.parentAlive.Close()

	var fileKey []byte
	var resultErr error
	if contextErr := c.ctx.Err(); contextErr != nil {
		resultErr = classError(contextClass(contextErr))
	} else if !protocolOK {
		resultErr = classError(ErrorHelper)
	} else {
		fileKey, resultErr = unmarshalResponse(response)
		if c.mode == ModeHardware && !readyReceived && resultErr == nil {
			secureClear(fileKey)
			fileKey = nil
			resultErr = classError(ErrorHelper)
		}
		if resultErr == nil && waitErr != nil {
			secureClear(fileKey)
			fileKey = nil
			resultErr = classError(ErrorHelper)
		}
	}
	clear(response)
	if resultErr == nil {
		secureLock(fileKey)
	}

	c.mu.Lock()
	c.fileKey = fileKey
	c.err = resultErr
	c.mu.Unlock()
	if c.mode == ModeHardware && !readyReceived {
		c.setReady(resultErr)
	}
	close(c.done)
	if c.onDone != nil {
		c.onDone(c)
	}
}

func (c *Call) closeStdin() (err error) {
	c.stdinClose.Do(func() { err = c.stdin.Close() })
	return err
}

func (c *Call) closeStdout() (err error) {
	c.stdoutClose.Do(func() { err = c.stdout.Close() })
	return err
}

func (c *Call) closeContinue() error {
	c.continueClose.Do(func() {
		if c.continueWriter != nil {
			c.continueCloseErr = c.continueWriter.Close()
		}
	})
	return c.continueCloseErr
}

func (c *Call) closePipes() {
	_ = c.closeStdin()
	_ = c.closeStdout()
	_ = c.closeContinue()
}

func (c *Call) setReady(err error) {
	c.readyOnce.Do(func() {
		c.mu.Lock()
		c.readyErr = err
		c.mu.Unlock()
		close(c.readyDone)
	})
}

// killHelperProcessGroup is called only by exchange, immediately before the
// sole Cmd.Wait call. A PID therefore cannot be reused between reap and signal.
func killHelperProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err == nil {
		return
	}
	_ = cmd.Process.Kill()
}

func configureHelperProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func sanitizedEnvironment(base []string, configPath string, mode Mode) []string {
	allowed := make([]string, 0, len(base)+4)
	seen := make(map[string]bool)
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || seen[name] || !allowedEnvironmentName(name) {
			continue
		}
		seen[name] = true
		allowed = append(allowed, entry)
	}
	allowed = append(allowed,
		internalModeEnvironment+"="+string(mode),
		"YUBITOUCH_CONFIG="+configPath,
		parentwatch.Environment(parentWatchEnvironment),
	)
	if mode == ModeHardware {
		allowed = append(allowed, hardwareContinueEnvironment+"=4")
	}
	return allowed
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

func closeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}
