//go:build !darwin

package ageipc

import (
	"net"
	"testing"
)

func TestPlatformPeerUIDFailsClosed(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if _, err := platformPeerUID(server); err == nil {
		t.Fatal("unsupported platform accepted peer credentials")
	}
}
