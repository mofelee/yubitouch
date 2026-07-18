package agentproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestLiveAgentSessionBindRoundTrip(t *testing.T) {
	socketPath := os.Getenv("YUBITOUCH_LIVE_AGENT_SOCKET")
	if socketPath == "" {
		t.Skip("set YUBITOUCH_LIVE_AGENT_SOCKET to run against a live YubiTouch agent")
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("agent returned %d keys, want exactly one configured target", len(keys))
	}
	target, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}

	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatal(err)
	}
	hostSignature, err := hostSigner.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}

	payload := ssh.Marshal(struct {
		HostKey      []byte
		SessionID    []byte
		Signature    []byte
		IsForwarding bool
	}{
		HostKey:      hostSigner.PublicKey().Marshal(),
		SessionID:    sessionID,
		Signature:    ssh.Marshal(*hostSignature),
		IsForwarding: false,
	})
	response, err := client.Extension(sessionBindExtension, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != 1 || response[0] != 6 {
		t.Fatalf("session-bind response = %v, want SSH_AGENT_SUCCESS", response)
	}

	data := []byte("YubiTouch live session-bind verification")
	signature, err := client.Sign(target, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Verify(data, signature); err != nil {
		t.Fatalf("verify target signature: %v", err)
	}
}
