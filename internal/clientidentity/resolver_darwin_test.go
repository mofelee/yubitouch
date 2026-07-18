//go:build darwin

package clientidentity

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPeerPIDAndRequesterFromUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "yt-identity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", path)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("sandbox does not permit Unix socket creation")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server net.Conn
	select {
	case server = <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("accept timed out")
	}

	pid, err := peerPID(server)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Fatalf("peer PID = %d, want %d", pid, os.Getpid())
	}
	started := time.Now()
	requester := Resolve(server)
	if time.Since(started) > 500*time.Millisecond {
		t.Fatalf("identity resolution exceeded latency bound: %s", time.Since(started))
	}
	if requester.Name == "" || requester.DirectClient == "" {
		t.Fatalf("requester = %+v", requester)
	}
	for _, value := range []string{requester.Name, requester.DirectClient, requester.BundleIdentifier} {
		if strings.Contains(value, string(filepath.Separator)) || strings.Contains(value, dir) {
			t.Fatalf("requester leaked a path: %+v", requester)
		}
	}
}
