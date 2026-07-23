package agehelper

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const resolverParentWatchDescriptor = 3

// startResolverParentLifetimeWatch monitors the same private fd3 lifetime
// pipe as other helpers, but permits the resolver to be a member of its direct
// parent's process group. The daemon owns that group and can therefore kill
// the persistent helper, resolver, and descendants atomically.
func startResolverParentLifetimeWatch(getenv func(string) string) (func(), error) {
	if getenv == nil || getenv(parentWatchEnvironment) != "3" {
		return nil, errors.New("PIN resolver parent watch is unavailable")
	}
	pid := os.Getpid()
	parentPID := os.Getppid()
	if pid <= 1 || parentPID <= 1 || syscall.Getpgrp() != parentPID {
		return nil, errors.New("PIN resolver does not share its helper parent process group")
	}
	var info syscall.Stat_t
	if err := syscall.Fstat(resolverParentWatchDescriptor, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return nil, errors.New("PIN resolver parent watch is not a pipe")
	}
	flags, err := unix.FcntlInt(uintptr(resolverParentWatchDescriptor), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errors.New("PIN resolver parent watch is not read-only")
	}
	if err := syscall.SetNonblock(resolverParentWatchDescriptor, true); err != nil {
		return nil, errors.New("PIN resolver parent watch cannot be monitored")
	}
	file := os.NewFile(uintptr(resolverParentWatchDescriptor), "pin-resolver-parent-watch")
	if file == nil {
		return nil, errors.New("PIN resolver parent watch descriptor is invalid")
	}
	syscall.CloseOnExec(resolverParentWatchDescriptor)

	watch := &resolverLifetimeWatch{file: file, done: make(chan struct{})}
	go watch.run()
	return watch.disarm, nil
}

type resolverLifetimeWatch struct {
	file *os.File
	done chan struct{}

	mu       sync.Mutex
	disarmed bool
	stop     sync.Once
}

func (w *resolverLifetimeWatch) run() {
	defer close(w.done)
	var unexpected [1]byte
	_, _ = w.file.Read(unexpected[:])
	w.mu.Lock()
	terminate := !w.disarmed
	w.mu.Unlock()
	if terminate {
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		os.Exit(helperFailureExitCode)
	}
}

func (w *resolverLifetimeWatch) disarm() {
	w.stop.Do(func() {
		w.mu.Lock()
		w.disarmed = true
		w.mu.Unlock()
		_ = w.file.Close()
		<-w.done
	})
}
