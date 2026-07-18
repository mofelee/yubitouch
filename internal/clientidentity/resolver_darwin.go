//go:build darwin

package clientidentity

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/mofelee/yubitouch/internal/signing"
	"golang.org/x/sys/unix"
	"howett.net/plist"
)

const (
	darwinSOLLocal       = 0
	darwinLocalPeerPID   = 2
	maxParentDepth       = 12
	identityLookupBudget = 100 * time.Millisecond
)

var bundleCache sync.Map

type infoPlist struct {
	DisplayName string `plist:"CFBundleDisplayName"`
	Name        string `plist:"CFBundleName"`
	Identifier  string `plist:"CFBundleIdentifier"`
}

func Resolve(conn net.Conn) signing.Requester {
	pid, err := peerPID(conn)
	if err != nil || pid <= 0 {
		return signing.Requester{Name: unknownRequester}
	}
	deadline := time.Now().Add(identityLookupBudget)
	chain := make([]processSnapshot, 0, maxParentDepth)
	seen := make(map[int]struct{}, maxParentDepth)
	for len(chain) < maxParentDepth && pid > 1 && time.Now().Before(deadline) {
		if _, exists := seen[pid]; exists {
			break
		}
		seen[pid] = struct{}{}
		process, parent, err := snapshotProcess(pid)
		if err != nil {
			break
		}
		chain = append(chain, process)
		pid = parent
	}
	return chooseRequester(chain)
}

func peerPID(conn net.Conn) (int, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("connection does not expose a system socket")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		pid, socketErr = unix.GetsockoptInt(int(fd), darwinSOLLocal, darwinLocalPeerPID)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	return pid, nil
}

func snapshotProcess(pid int) (processSnapshot, int, error) {
	before, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(before.Proc.P_pid) != pid {
		return processSnapshot{}, 0, errors.New("process is unavailable")
	}
	path, _ := processExecutablePath(pid)
	after, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(after.Proc.P_pid) != pid {
		return processSnapshot{}, 0, errors.New("process exited during identity lookup")
	}
	if before.Proc.P_starttime.Sec != after.Proc.P_starttime.Sec ||
		before.Proc.P_starttime.Usec != after.Proc.P_starttime.Usec ||
		before.Eproc.Ppid != after.Eproc.Ppid {
		return processSnapshot{}, 0, errors.New("process identity changed during lookup")
	}
	executable := filepath.Base(path)
	if executable == "." || executable == string(filepath.Separator) || executable == "" {
		executable = cString(before.Proc.P_comm[:])
	}
	process := processSnapshot{
		executable: executable,
		path:       path,
	}
	if bundlePath := enclosingBundle(path); bundlePath != "" {
		process.bundle = loadBundleMetadata(bundlePath, pid)
	}
	return process, int(before.Eproc.Ppid), nil
}

func processExecutablePath(pid int) (string, error) {
	data, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(data) <= 4 {
		return "", errors.New("process arguments are truncated")
	}
	value := data[4:]
	end := bytes.IndexByte(value, 0)
	if end <= 0 {
		return "", errors.New("process executable path is unavailable")
	}
	path := filepath.Clean(string(value[:end]))
	if !filepath.IsAbs(path) {
		return "", errors.New("process executable path is not absolute")
	}
	return path, nil
}

func loadBundleMetadata(path string, pid int) bundleMetadata {
	if cached, ok := bundleCache.Load(path); ok {
		return cached.(bundleMetadata)
	}
	metadata := bundleMetadata{
		name:     sanitizeDisplay(stringsTrimApp(filepath.Base(path))),
		verified: codeSignatureValid(pid),
	}
	data, err := os.ReadFile(filepath.Join(path, "Contents", "Info.plist"))
	if err == nil {
		var info infoPlist
		if _, err := plist.Unmarshal(data, &info); err == nil {
			if name := sanitizeDisplay(firstNonEmpty(info.DisplayName, info.Name)); name != "" {
				metadata.name = name
			}
			metadata.identifier = sanitizeBundleIdentifier(info.Identifier)
		}
	}
	bundleCache.Store(path, metadata)
	return metadata
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func stringsTrimApp(value string) string {
	if len(value) >= 4 && value[len(value)-4:] == ".app" {
		return value[:len(value)-4]
	}
	return value
}

func cString(value []byte) string {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return string(value)
}
