//go:build darwin

package ageipc

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func platformPeerUID(conn net.Conn) (uint32, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New("connection does not expose a system socket")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Xucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	if credential == nil {
		return 0, errors.New("peer credential is unavailable")
	}
	return credential.Uid, nil
}
