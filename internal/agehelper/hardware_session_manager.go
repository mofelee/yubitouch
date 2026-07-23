package agehelper

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/mofelee/yubitouch/internal/parentwatch"
)

// HardwareManager owns at most one persistent, authenticated hardware helper.
// It is safe for concurrent invalidation, but permits only one active request;
// the daemon's global signing coordinator provides the normal serialization.
type HardwareManager struct {
	executable   string
	configPath   string
	timeout      time.Duration
	environment  []string
	command      commandFactory
	requestLimit int

	lifecycle sync.Mutex
	mu        sync.Mutex
	process   *hardwareProcess
	active    *HardwareCall
	closed    bool
	poisoned  bool
}

// NewHardwareManager creates a daemon-owned hardware session manager.
// executable must be the current signed yubitouch executable.
func NewHardwareManager(executable, configPath string, timeout time.Duration) *HardwareManager {
	if executable == "" {
		executable, _ = os.Executable()
	}
	return &HardwareManager{
		executable:  executable,
		configPath:  configPath,
		timeout:     timeout,
		environment: append([]string(nil), os.Environ()...),
		command: func(path string) *exec.Cmd {
			return exec.Command(path)
		},
		requestLimit: maxRetainedRequestIDs,
	}
}

// Run performs one complete request. Callers that display touch UI should use
// Start, WaitReady, and Wait so the UI remains outside the coordinator call.
func (m *HardwareManager) Run(ctx context.Context, request Request) ([]byte, error) {
	call, err := m.Start(ctx, request)
	if err != nil {
		return nil, err
	}
	return call.Wait()
}

// Start registers one request and begins the strict session exchange.
func (m *HardwareManager) Start(ctx context.Context, request Request) (*HardwareCall, error) {
	if m == nil {
		return nil, classError(ErrorHelper)
	}
	requestID, err := newRequestIdentifier()
	if err != nil {
		return nil, err
	}
	continuationID, err := newContinuationIdentifier()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var callCtx context.Context
	var cancel context.CancelFunc
	if m.timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, m.timeout)
	} else {
		callCtx, cancel = context.WithCancel(ctx)
	}
	if err := callCtx.Err(); err != nil {
		cancel()
		return nil, classError(contextClass(err))
	}
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.poisoned || m.active != nil || callCtx.Err() != nil || !validExecutable(m.executable) ||
		!validConfigPath(m.configPath) || m.command == nil {
		contextErr := callCtx.Err()
		cancel()
		if contextErr != nil {
			return nil, classError(contextClass(contextErr))
		}
		return nil, classError(ErrorHelper)
	}
	process := m.process
	launched := false
	stopLaunched := func() error {
		if !launched || process == nil {
			return nil
		}
		if m.process == process {
			m.process = nil
		}
		if cleanupErr := process.stop(); cleanupErr != nil {
			m.poisoned = true
			return cleanupErr
		}
		return nil
	}
	canceledStart := func(contextErr error) error {
		cancel()
		if cleanupErr := stopLaunched(); cleanupErr != nil {
			return cleanupErr
		}
		return classError(contextClass(contextErr))
	}
	requestLimit := m.requestLimit
	if requestLimit <= 0 || requestLimit > maxRetainedRequestIDs {
		requestLimit = maxRetainedRequestIDs
	}
	if process != nil && (process.isStopped() || process.completedRequests >= requestLimit) {
		m.process = nil
		if err := process.stop(); err != nil {
			m.poisoned = true
			cancel()
			return nil, err
		}
		process = nil
	}
	if contextErr := callCtx.Err(); contextErr != nil {
		return nil, canceledStart(contextErr)
	}
	if process == nil {
		process, err = m.launchProcess()
		if err != nil {
			cancel()
			return nil, err
		}
		launched = true
		m.process = process
	}
	if contextErr := callCtx.Err(); contextErr != nil {
		return nil, canceledStart(contextErr)
	}
	encoded, err := marshalSessionRequest(process.sessionID, requestID, request)
	if err != nil {
		cancel()
		if m.process == process && process.isStopped() {
			m.process = nil
		}
		return nil, err
	}
	if contextErr := callCtx.Err(); contextErr != nil {
		clear(encoded)
		return nil, canceledStart(contextErr)
	}
	delivery, err := process.register()
	if err != nil {
		clear(encoded)
		cancel()
		if m.process == process {
			m.process = nil
		}
		if cleanupErr := process.stop(); cleanupErr != nil {
			m.poisoned = true
			return nil, cleanupErr
		}
		return nil, err
	}
	if contextErr := callCtx.Err(); contextErr != nil {
		clear(encoded)
		process.unregister(delivery)
		return nil, canceledStart(contextErr)
	}
	call := &HardwareCall{
		manager:        m,
		process:        process,
		delivery:       delivery,
		requestID:      requestID,
		continuationID: continuationID,
		ctx:            callCtx,
		cancel:         cancel,
		readyDone:      make(chan struct{}),
		done:           make(chan struct{}),
		watchStop:      make(chan struct{}),
		watchDone:      make(chan struct{}),
	}
	m.active = call
	go call.exchange(encoded)
	go call.watchContext()
	return call, nil
}

// Invalidate destroys and reaps the retained helper. An active request is
// canceled because its PKCS#11 state can no longer be known or reused.
func (m *HardwareManager) Invalidate() error {
	if m == nil {
		return nil
	}
	return m.invalidate(false)
}

// Close permanently closes the manager and reaps its helper.
func (m *HardwareManager) Close() error {
	if m == nil {
		return nil
	}
	return m.invalidate(true)
}

// CancelCurrent cancels and reaps the active helper request, if any.
func (m *HardwareManager) CancelCurrent() {
	if m == nil {
		return
	}
	m.mu.Lock()
	call := m.active
	m.mu.Unlock()
	if call != nil {
		call.Cancel()
	}
}

func (m *HardwareManager) invalidate(closeManager bool) error {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.mu.Lock()
	if closeManager {
		m.closed = true
	}
	process := m.process
	call := m.active
	m.process = nil
	m.mu.Unlock()
	if call != nil {
		call.cancel()
	}
	var cleanupErr error
	if process != nil {
		cleanupErr = process.stop()
	}
	if call != nil {
		<-call.done
	}
	m.mu.Lock()
	if cleanupErr != nil {
		m.poisoned = true
	}
	poisoned := m.poisoned
	m.mu.Unlock()
	if cleanupErr == nil && poisoned {
		cleanupErr = classError(ErrorHelper)
	}
	return cleanupErr
}

func (m *HardwareManager) launchProcess() (*hardwareProcess, error) {
	sessionID, err := newSessionIdentifier()
	if err != nil {
		return nil, err
	}
	cmd := m.command(m.executable)
	if cmd == nil {
		return nil, classError(ErrorHelper)
	}
	cmd.Env = sanitizedInternalEnvironment(m.environment, m.configPath, internalHardwareSessionMode,
		sessionIDEnvironment+"="+hex.EncodeToString(sessionID[:]),
	)
	cmd.Stderr = io.Discard
	configureHelperProcess(cmd)
	parentWatch, parentAlive, err := parentwatch.Attach(cmd)
	if err != nil {
		return nil, classError(ErrorHelper)
	}
	requestReader, requestWriter, err := os.Pipe()
	if err != nil {
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		return nil, classError(ErrorHelper)
	}
	responseReader, responseWriter, err := os.Pipe()
	if err != nil {
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		return nil, classError(ErrorHelper)
	}
	cmd.Stdin = requestReader
	cmd.Stdout = responseWriter
	if err := cmd.Start(); err != nil {
		_ = requestReader.Close()
		_ = requestWriter.Close()
		_ = responseReader.Close()
		_ = responseWriter.Close()
		_ = parentWatch.Close()
		_ = parentAlive.Close()
		return nil, classError(ErrorHelper)
	}
	_ = requestReader.Close()
	_ = responseWriter.Close()
	_ = parentWatch.Close()
	process := &hardwareProcess{
		manager:        m,
		sessionID:      sessionID,
		cmd:            cmd,
		requestWriter:  requestWriter,
		responseReader: responseReader,
		parentAlive:    parentAlive,
		stopped:        make(chan struct{}),
	}
	go process.readResponses()
	return process, nil
}

func (m *HardwareManager) processExited(process *hardwareProcess, cleanupErr error) {
	m.mu.Lock()
	if m.process == process {
		m.process = nil
	}
	if cleanupErr != nil {
		m.poisoned = true
	}
	m.mu.Unlock()
}

func (m *HardwareManager) poison() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.poisoned = true
	m.mu.Unlock()
}

func (m *HardwareManager) finish(call *HardwareCall, retain bool) {
	call.process.unregister(call.delivery)
	m.mu.Lock()
	if m.active == call {
		m.active = nil
	}
	if !retain && m.process == call.process {
		m.process = nil
	}
	if retain {
		call.process.completedRequests++
	}
	m.mu.Unlock()
}

type processDelivery struct {
	frames chan []byte
	done   chan struct{}
	close  sync.Once
}

func (d *processDelivery) stop() {
	if d != nil {
		d.close.Do(func() { close(d.done) })
	}
}

type hardwareProcess struct {
	manager   *HardwareManager
	sessionID sessionIdentifier
	cmd       *exec.Cmd

	requestWriter  io.WriteCloser
	responseReader io.ReadCloser
	parentAlive    io.Closer

	writeMu  sync.Mutex
	mu       sync.Mutex
	delivery *processDelivery

	stopOnce  sync.Once
	stopped   chan struct{}
	stopErr   error
	waitGroup func(int, time.Duration) bool

	completedRequests int
}

func (p *hardwareProcess) register() (*processDelivery, error) {
	if p == nil {
		return nil, classError(ErrorHelper)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.delivery != nil || p.isStopped() {
		return nil, classError(ErrorHelper)
	}
	delivery := &processDelivery{frames: make(chan []byte), done: make(chan struct{})}
	p.delivery = delivery
	return delivery, nil
}

func (p *hardwareProcess) unregister(delivery *processDelivery) {
	if p == nil || delivery == nil {
		return
	}
	p.mu.Lock()
	if p.delivery == delivery {
		p.delivery = nil
	}
	p.mu.Unlock()
	delivery.stop()
}

func (p *hardwareProcess) write(payload []byte, limit int) error {
	if p == nil || p.isStopped() {
		return classError(ErrorHelper)
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.isStopped() || writeFrame(p.requestWriter, payload, limit) != nil {
		return classError(ErrorHelper)
	}
	return nil
}

func (p *hardwareProcess) readResponses() {
	defer func() {
		cleanupErr := p.stop()
		if p.manager != nil {
			p.manager.processExited(p, cleanupErr)
		}
	}()
	for {
		payload, err := readFrame(p.responseReader, maxSessionResponseFrame)
		if err != nil {
			return
		}
		p.mu.Lock()
		delivery := p.delivery
		p.mu.Unlock()
		if delivery == nil {
			clear(payload)
			return
		}
		select {
		case delivery.frames <- payload:
		case <-delivery.done:
			clear(payload)
			return
		case <-p.stopped:
			clear(payload)
			return
		}
	}
}

func (p *hardwareProcess) stop() error {
	if p == nil || p.stopped == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		processGroup := 0
		if p.cmd != nil && p.cmd.Process != nil {
			processGroup = p.cmd.Process.Pid
		}
		_ = p.requestWriter.Close()
		_ = p.responseReader.Close()
		killHelperProcessGroup(p.cmd)
		if p.cmd != nil {
			_ = p.cmd.Wait()
		}
		if p.parentAlive != nil {
			_ = p.parentAlive.Close()
		}
		p.mu.Lock()
		waitGroup := p.waitGroup
		p.mu.Unlock()
		if waitGroup == nil {
			waitGroup = waitForHelperProcessGroup
		}
		if processGroup > 1 && !waitGroup(processGroup, 2*time.Second) {
			p.stopErr = classError(ErrorHelper)
		}
		close(p.stopped)
	})
	<-p.stopped
	return p.stopErr
}

func waitForHelperProcessGroup(processGroup int, timeout time.Duration) bool {
	if processGroup <= 1 || timeout <= 0 {
		return false
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Kill(-processGroup, 0)
		if errors.Is(err, syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

func (p *hardwareProcess) isStopped() bool {
	if p == nil || p.stopped == nil {
		return true
	}
	select {
	case <-p.stopped:
		return true
	default:
		return false
	}
}

// HardwareCall is one request through a HardwareManager. WaitReady returns
// only after session validation and ready_for_touch. Wait then sends continue
// and waits for the derived file key.
type HardwareCall struct {
	manager        *HardwareManager
	process        *hardwareProcess
	delivery       *processDelivery
	requestID      requestIdentifier
	continuationID continuationIdentifier
	ctx            context.Context
	cancel         context.CancelFunc

	readyDone    chan struct{}
	done         chan struct{}
	watchStop    chan struct{}
	watchDone    chan struct{}
	readyOnce    sync.Once
	watchOnce    sync.Once
	continueOnce sync.Once

	mu          sync.Mutex
	readyErr    error
	continueErr error
	fileKey     []byte
	err         error
	resultTaken bool
}

// WaitReady waits for both session_ready and ready_for_touch. Early failures
// are returned only after the failed helper has been killed and reaped.
func (c *HardwareCall) WaitReady() error {
	if c == nil || c.readyDone == nil {
		return classError(ErrorHelper)
	}
	<-c.readyDone
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readyErr
}

// Wait sends the single bound continue frame and waits for the result.
func (c *HardwareCall) Wait() ([]byte, error) {
	if c == nil || c.done == nil {
		return nil, classError(ErrorHelper)
	}
	if err := c.WaitReady(); err != nil {
		return nil, err
	}
	c.continueOnce.Do(func() {
		encoded, err := marshalSessionContinue(c.process.sessionID, c.requestID, c.continuationID)
		if err == nil {
			err = c.process.write(encoded, maxSessionResponseFrame)
		}
		clear(encoded)
		if err != nil {
			c.mu.Lock()
			if c.ctx.Err() != nil {
				c.continueErr = classError(contextClass(c.ctx.Err()))
			} else {
				c.continueErr = classError(ErrorHelper)
			}
			c.mu.Unlock()
			_ = c.process.stop()
		}
	})
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.continueErr != nil {
		secureClear(c.fileKey)
		c.fileKey = nil
		return nil, c.continueErr
	}
	if c.err != nil {
		return nil, c.err
	}
	if c.resultTaken || len(c.fileKey) != fileKeySize {
		return nil, classError(ErrorHelper)
	}
	fileKey := c.fileKey
	c.fileKey = nil
	c.resultTaken = true
	return fileKey, nil
}

// Cancel invalidates the entire authenticated helper and waits for it to be
// reaped. A later request therefore starts with a new PIN resolver and login.
func (c *HardwareCall) Cancel() {
	if c == nil || c.done == nil {
		return
	}
	select {
	case <-c.done:
		return
	default:
	}
	c.cancel()
	_ = c.process.stop()
	<-c.done
}

func (c *HardwareCall) watchContext() {
	defer close(c.watchDone)
	select {
	case <-c.ctx.Done():
		_ = c.process.stop()
	case <-c.watchStop:
	case <-c.done:
	}
}

func (c *HardwareCall) exchange(encoded []byte) {
	defer clear(encoded)
	if err := c.ctx.Err(); err != nil {
		c.finishFailure(classError(contextClass(err)))
		return
	}
	if err := c.process.write(encoded, maxSessionRequestFrame); err != nil {
		c.finishFailure(classError(ErrorHelper))
		return
	}

	first, err := c.nextFrame()
	if err != nil {
		c.finishFailure(err)
		return
	}
	if err := unmarshalSessionReady(first, c.process.sessionID, c.requestID); err != nil {
		resultErr := unmarshalSessionEarlyResult(first, c.process.sessionID, c.requestID)
		clear(first)
		c.finishFailure(resultErr)
		return
	}
	clear(first)

	second, err := c.nextFrame()
	if err != nil {
		c.finishFailure(err)
		return
	}
	if err := unmarshalSessionReadyForTouch(second, c.process.sessionID, c.requestID); err != nil {
		resultErr := unmarshalSessionEarlyResult(second, c.process.sessionID, c.requestID)
		clear(second)
		c.finishFailure(resultErr)
		return
	}
	clear(second)
	c.setReady(nil)

	result, err := c.nextFrame()
	if err != nil {
		c.finishFailure(err)
		return
	}
	fileKey, resultErr := unmarshalSessionResult(result, c.process.sessionID, c.requestID, c.continuationID)
	clear(result)
	if c.ctx.Err() != nil {
		secureClear(fileKey)
		c.finishFailure(classError(contextClass(c.ctx.Err())))
		return
	}
	if resultErr != nil {
		secureClear(fileKey)
		c.finishFailure(resultErr)
		return
	}
	secureLock(fileKey)
	c.finish(fileKey, nil, true)
}

func (c *HardwareCall) nextFrame() ([]byte, error) {
	select {
	case payload := <-c.delivery.frames:
		return payload, nil
	case <-c.process.stopped:
		if c.ctx.Err() != nil {
			return nil, classError(contextClass(c.ctx.Err()))
		}
		return nil, classError(ErrorHelper)
	case <-c.ctx.Done():
		return nil, classError(contextClass(c.ctx.Err()))
	}
}

func (c *HardwareCall) finishFailure(err error) {
	cleanupErr := c.process.stop()
	if cleanupErr != nil {
		err = cleanupErr
		c.manager.poison()
	} else if c.ctx.Err() != nil {
		err = classError(contextClass(c.ctx.Err()))
	}
	c.finish(nil, err, false)
}

func (c *HardwareCall) finish(fileKey []byte, err error, retain bool) {
	if !retain {
		secureClear(fileKey)
		fileKey = nil
	}
	c.mu.Lock()
	c.fileKey = fileKey
	c.err = err
	c.mu.Unlock()
	c.watchOnce.Do(func() { close(c.watchStop) })
	<-c.watchDone
	c.cancel()
	if c.manager != nil {
		c.manager.finish(c, retain)
	}
	close(c.done)
	if err != nil {
		c.setReady(err)
	}
}

func (c *HardwareCall) setReady(err error) {
	c.readyOnce.Do(func() {
		c.mu.Lock()
		c.readyErr = err
		c.mu.Unlock()
		close(c.readyDone)
	})
}
