//go:build darwin

package ageipc

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPlatformPeerUID(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "peer-credential-test")
	if file == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatal("could not wrap socket")
	}
	_ = unix.Close(fds[1])
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, err := platformPeerUID(conn)
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Geteuid()) {
		t.Fatalf("peer EUID = %d, want current EUID", uid)
	}
}
