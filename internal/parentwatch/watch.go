package parentwatch

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const fileDescriptor = 3

// Attach reserves descriptor 3 in cmd for a parent-lifetime pipe. The caller
// must close watchEnd after Cmd.Start and keep parentAlive open until Cmd.Wait
// returns. Kernel closure of parentAlive then identifies launcher death
// without PID reuse or reparenting races.
func Attach(cmd *exec.Cmd) (watchEnd, parentAlive *os.File, err error) {
	if cmd == nil || len(cmd.ExtraFiles) != 0 {
		return nil, nil, errors.New("helper parent watch cannot be attached")
	}
	watchEnd, parentAlive, err = os.Pipe()
	if err != nil {
		return nil, nil, errors.New("helper parent watch pipe is unavailable")
	}
	cmd.ExtraFiles = []*os.File{watchEnd}
	return watchEnd, parentAlive, nil
}

// Environment returns the fixed environment entry that identifies the
// inherited watch descriptor to a helper.
func Environment(name string) string {
	if !validEnvironmentName(name) {
		return ""
	}
	return name + "=3"
}

// Start validates and monitors the inherited parent-lifetime pipe. The helper
// must already be the leader of its own process group so parent loss can kill
// the helper and descendants without signaling an unrelated process.
func Start(getenv func(string) string, environmentName string, failureExitCode int) (func(), error) {
	if getenv == nil || !validEnvironmentName(environmentName) || getenv(environmentName) != "3" {
		return nil, errors.New("helper parent watch is unavailable")
	}
	if failureExitCode <= 0 || failureExitCode > 125 {
		return nil, errors.New("helper parent watch exit code is invalid")
	}
	if os.Getpid() <= 1 || syscall.Getpgrp() != os.Getpid() {
		return nil, errors.New("helper does not own its process group")
	}

	if err := validateWatchDescriptor(fileDescriptor); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileDescriptor), "helper-parent-watch")
	if file == nil {
		return nil, errors.New("helper parent watch descriptor is invalid")
	}
	syscall.CloseOnExec(fileDescriptor)

	watch := &lifetimeWatch{
		file: file,
		terminate: func() {
			terminateProcessGroup(failureExitCode)
		},
		done: make(chan struct{}),
	}
	go watch.run()
	return watch.disarm, nil
}

type lifetimeWatch struct {
	file      *os.File
	terminate func()
	done      chan struct{}

	mu       sync.Mutex
	disarmed bool
	stop     sync.Once
}

func (w *lifetimeWatch) run() {
	defer close(w.done)
	var unexpected [1]byte
	_, _ = w.file.Read(unexpected[:])

	w.mu.Lock()
	terminate := !w.disarmed
	w.mu.Unlock()
	if terminate {
		w.terminate()
	}
}

func (w *lifetimeWatch) disarm() {
	w.stop.Do(func() {
		w.mu.Lock()
		w.disarmed = true
		w.mu.Unlock()
		_ = w.file.Close()
		<-w.done
	})
}

func terminateProcessGroup(exitCode int) {
	pid := os.Getpid()
	if pid > 1 && syscall.Getpgrp() == pid {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	// If group signaling is unavailable or fails, do not leave the helper alive
	// without the process that owns its deadline.
	os.Exit(exitCode)
}

func validEnvironmentName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "=\x00")
}

func validateWatchDescriptor(fd int) error {
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return errors.New("helper parent watch is not a pipe")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return errors.New("helper parent watch is not read-only")
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		return errors.New("helper parent watch cannot be monitored")
	}
	return nil
}
