package launchagent

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"howett.net/plist"
)

const Label = "com.github.mofelee.yubitouch"

type launchdPlist struct {
	Label                  string   `plist:"Label"`
	ProgramArguments       []string `plist:"ProgramArguments"`
	RunAtLoad              bool     `plist:"RunAtLoad"`
	KeepAlive              bool     `plist:"KeepAlive"`
	ProcessType            string   `plist:"ProcessType"`
	LimitLoadToSessionType string   `plist:"LimitLoadToSessionType"`
	StandardOutPath        string   `plist:"StandardOutPath"`
	StandardErrorPath      string   `plist:"StandardErrorPath"`
}

func PlistPath(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist")
}

func Write(home string, executable string, configPath string) (string, error) {
	path := PlistPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	value := launchdPlist{
		Label:                  Label,
		ProgramArguments:       []string{executable, "daemon", "--config", configPath},
		RunAtLoad:              true,
		KeepAlive:              true,
		ProcessType:            "Background",
		LimitLoadToSessionType: "Aqua",
		StandardOutPath:        "/dev/null",
		StandardErrorPath:      "/dev/null",
	}
	data, err := plist.MarshalIndent(value, plist.XMLFormat, "\t")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".yubitouch-plist-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(name, path); err != nil {
		return "", err
	}
	return path, nil
}

func Ensure(ctx context.Context, home string, executable string, configPath string) error {
	path, err := Write(home, executable, configPath)
	if err != nil {
		return err
	}
	target := serviceTarget()
	if command(ctx, "print", target) == nil {
		return command(ctx, "kickstart", target)
	}
	if err := command(ctx, "bootstrap", domainTarget(), path); err != nil {
		return err
	}
	return command(ctx, "kickstart", target)
}

func Reload(ctx context.Context, home string, executable string, configPath string) error {
	path, err := Write(home, executable, configPath)
	if err != nil {
		return err
	}
	_ = command(ctx, "bootout", serviceTarget())
	if err := command(ctx, "bootstrap", domainTarget(), path); err != nil {
		return err
	}
	return command(ctx, "kickstart", serviceTarget())
}

func Stop(ctx context.Context) error {
	if !IsLoaded(ctx) {
		return nil
	}
	return command(ctx, "bootout", serviceTarget())
}

func IsLoaded(ctx context.Context) bool {
	return command(ctx, "print", serviceTarget()) == nil
}

func WaitForSocket(ctx context.Context, path string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&netDialer{}).dial(path)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func command(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "/bin/launchctl", args...)
	var stderr bytes.Buffer
	cmd.Stdout = ioDiscard{}
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launchctl %v: %w: %s", args, err, stderr.String())
	}
	return nil
}

func domainTarget() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

func serviceTarget() string {
	return domainTarget() + "/" + Label
}

type closeConn interface {
	Close() error
}

type netDialer struct{}

func (netDialer) dial(path string) (closeConn, error) {
	return net.DialTimeout("unix", path, 100*time.Millisecond)
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
