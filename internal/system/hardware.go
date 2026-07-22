package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mofelee/yubitouch/internal/config"
	"github.com/mofelee/yubitouch/native/macos"
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
	return probeYubiKeys(ctx, macos.CountYubiKeys)
}

func probeYubiKeys(ctx context.Context, countDevices func() (int, error)) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	count, err := countDevices()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrDeviceProbe, err)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

type YubiKeyMonitor struct {
	native *macos.YubiKeyMonitor
}

func NewYubiKeyMonitor() (*YubiKeyMonitor, error) {
	monitor, err := macos.NewYubiKeyMonitor()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeviceProbe, err)
	}
	return &YubiKeyMonitor{native: monitor}, nil
}

func (m *YubiKeyMonitor) Probe(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	count, err := m.native.Count()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrDeviceProbe, err)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func (m *YubiKeyMonitor) Events() <-chan struct{} {
	return m.native.Events()
}

func (m *YubiKeyMonitor) Close() error {
	return m.native.Close()
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
