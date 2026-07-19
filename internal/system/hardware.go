package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mofelee/yubitouch/internal/config"
	"golang.org/x/crypto/ssh"
)

var (
	ErrYKManUnavailable  = errors.New("ykman is not installed")
	ErrDeviceProbe       = errors.New("cannot query connected YubiKeys")
	ErrDeviceNotDetected = errors.New("no YubiKey was detected")
)

type HardwareReport struct {
	DeviceCount       int
	SlotAlgorithm     string
	PINPolicy         string
	TouchPolicy       string
	TargetKeyFound    bool
	OtherProviderKeys int
}

func ProbeYubiKeys(ctx context.Context) (int, error) {
	return probeYubiKeys(ctx, lookupYKMan, commandOutput)
}

func lookupYKMan(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	for _, path := range []string{"/opt/homebrew/bin/ykman", "/usr/local/bin/ykman"} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", ErrYKManUnavailable
}

type pathLookup func(string) (string, error)

type outputRunner func(context.Context, string, ...string) ([]byte, []byte, error)

func probeYubiKeys(ctx context.Context, lookup pathLookup, run outputRunner) (int, error) {
	ykman, err := lookup("ykman")
	if err != nil {
		return 0, ErrYKManUnavailable
	}
	serialOutput, diagnosticOutput, err := run(ctx, ykman, "list", "--serials")
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("%w: %v", ErrDeviceProbe, err)
	}
	count := countNonEmptyLines(serialOutput)
	if count == 0 && len(bytes.TrimSpace(diagnosticOutput)) != 0 {
		return 0, ErrDeviceProbe
	}
	return count, nil
}

func commandOutput(ctx context.Context, path string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func InspectHardware(ctx context.Context, cfg config.Config, deps Dependencies) (HardwareReport, error) {
	return inspectHardware(ctx, cfg, deps, ProbeYubiKeys)
}

func inspectHardware(ctx context.Context, cfg config.Config, deps Dependencies, probe func(context.Context) (int, error)) (HardwareReport, error) {
	deviceCount, err := probe(ctx)
	if err != nil {
		return HardwareReport{}, err
	}
	report := HardwareReport{DeviceCount: deviceCount}
	if report.DeviceCount == 0 {
		return report, ErrDeviceNotDetected
	}
	ykman, err := exec.LookPath("ykman")
	if err != nil {
		return report, ErrYKManUnavailable
	}

	metadata, err := exec.CommandContext(ctx, ykman, "piv", "keys", "info", "9a").Output()
	if err != nil {
		return report, fmt.Errorf("cannot inspect PIV slot 9A: %w", err)
	}
	fields := parseMetadata(metadata)
	report.SlotAlgorithm = fields["Algorithm"]
	report.PINPolicy = fields["PIN required for use"]
	report.TouchPolicy = fields["Touch required for use"]

	providerOutput, err := exec.CommandContext(ctx, deps.SSHKeygen, "-D", deps.YKCS11).Output()
	if err != nil {
		return report, fmt.Errorf("cannot enumerate YKCS11 public keys: %w", err)
	}
	report.TargetKeyFound, report.OtherProviderKeys = inspectProviderKeys(providerOutput, cfg.PublicKey)
	return report, nil
}

func inspectProviderKeys(output []byte, target ssh.PublicKey) (bool, int) {
	found := false
	other := 0
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		if target != nil && bytes.Equal(key.Marshal(), target.Marshal()) {
			found = true
		} else {
			other++
		}
	}
	return found, other
}

func parseMetadata(output []byte) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return fields
}

func countNonEmptyLines(output []byte) int {
	count := 0
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) != 0 {
			count++
		}
	}
	return count
}
