package agehelper

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/mofelee/yubitouch/internal/parentwatch"
	"golang.org/x/sys/unix"
)

func TestValidateHardwareContinueDescriptorRequiresReadOnlyPipeAndSetsCloseOnExec(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()

	flags, err := unix.FcntlInt(readEnd.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(readEnd.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err := validateHardwareContinueDescriptor(int(readEnd.Fd())); err != nil {
		t.Fatalf("read end was rejected: %v", err)
	}
	flags, err = unix.FcntlInt(readEnd.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("descriptor flags = %#x, err = %v", flags, err)
	}

	if err := validateHardwareContinueDescriptor(int(writeEnd.Fd())); err == nil {
		t.Fatal("write end was accepted as a continue descriptor")
	}

	regular, err := os.OpenFile(t.TempDir()+"/continue", os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if err := validateHardwareContinueDescriptor(int(regular.Fd())); err == nil {
		t.Fatal("regular file was accepted as a continue descriptor")
	}
}

func TestHardwareContinueSignalRequiresOneTokenAndEOF(t *testing.T) {
	for name, test := range map[string]struct {
		payload []byte
		valid   bool
	}{
		"valid":     {[]byte{hardwareContinueSignal}, true},
		"empty":     {nil, false},
		"wrong":     {[]byte{hardwareContinueSignal + 1}, false},
		"duplicate": {[]byte{hardwareContinueSignal, hardwareContinueSignal}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := readHardwareContinue(bytes.NewReader(test.payload))
			if (err == nil) != test.valid {
				t.Fatalf("valid = %t, err = %v", test.valid, err)
			}
		})
	}
	if err := readHardwareContinue(nil); err == nil {
		t.Fatal("nil continue reader was accepted")
	}

	var output bytes.Buffer
	if err := writeHardwareContinue(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), []byte{hardwareContinueSignal}) {
		t.Fatalf("continue signal = %v", output.Bytes())
	}
	if err := writeHardwareContinue(nil); err == nil {
		t.Fatal("nil continue writer was accepted")
	}
}

func TestAttachHardwareContinueUsesDescriptorAfterParentWatch(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	watchEnd, parentAlive, err := parentwatch.Attach(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer watchEnd.Close()
	defer parentAlive.Close()

	childRead, parentWrite, err := attachHardwareContinue(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer childRead.Close()
	defer parentWrite.Close()
	if len(cmd.ExtraFiles) != 2 || cmd.ExtraFiles[0] != watchEnd || cmd.ExtraFiles[1] != childRead {
		t.Fatal("continue descriptor was not attached after the parent-watch descriptor")
	}

	if _, _, err := attachHardwareContinue(exec.Command("/usr/bin/true")); err == nil {
		t.Fatal("continue descriptor was attached without a parent-watch descriptor")
	}
}

func TestOpenHardwareContinueRequiresFixedEnvironment(t *testing.T) {
	for name, getenv := range map[string]func(string) string{
		"nil":   nil,
		"empty": func(string) string { return "" },
		"wrong": func(string) string { return "5" },
	} {
		t.Run(name, func(t *testing.T) {
			reader, err := openHardwareContinue(getenv)
			if reader != nil {
				reader.Close()
			}
			if err == nil {
				t.Fatal("invalid continue environment was accepted")
			}
		})
	}
}
