package backend

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mofelee/yubitouch/internal/config"
	"golang.org/x/crypto/ssh"
)

func TestLiveFallbackTargetKey(t *testing.T) {
	socket := os.Getenv("YUBITOUCH_LIVE_FALLBACK_SOCKET")
	publicKeyPath := os.Getenv("YUBITOUCH_LIVE_PUBLIC_KEY")
	if socket == "" || publicKeyPath == "" {
		t.Skip("set YUBITOUCH_LIVE_FALLBACK_SOCKET and YUBITOUCH_LIVE_PUBLIC_KEY to inspect a live fallback agent")
	}
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	target, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		PublicKey:           target,
		FallbackAgent:       config.FallbackAgent1Password,
		FallbackAgentSocket: socket,
		SocketPath:          socket + ".public-not-used",
		BackendSocketPath:   socket + ".backend-not-used",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := InspectFallback(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Reachable || !report.TargetKeyFound {
		t.Fatalf("fallback report = %+v", report)
	}
	t.Logf("target key found; %d non-target key(s) filtered", report.OtherKeys)
}
