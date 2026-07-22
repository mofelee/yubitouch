package agehelper

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	hardwareContinueEnvironment = "YUBITOUCH_INTERNAL_AGE_CONTINUE_FD"
	hardwareContinueDescriptor  = 4
	hardwareContinueSignal      = byte(1)
)

func attachHardwareContinue(cmd *exec.Cmd) (childRead, parentWrite *os.File, err error) {
	if cmd == nil || len(cmd.ExtraFiles) != 1 {
		return nil, nil, errors.New("age helper continue pipe cannot be attached")
	}
	childRead, parentWrite, err = os.Pipe()
	if err != nil {
		return nil, nil, errors.New("age helper continue pipe is unavailable")
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, childRead)
	return childRead, parentWrite, nil
}

func openHardwareContinue(getenv func(string) string) (io.ReadCloser, error) {
	if getenv == nil || getenv(hardwareContinueEnvironment) != "4" {
		return nil, errors.New("age helper continue pipe is unavailable")
	}
	if err := validateHardwareContinueDescriptor(hardwareContinueDescriptor); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(hardwareContinueDescriptor), "age-helper-continue")
	if file == nil {
		return nil, errors.New("age helper continue descriptor is invalid")
	}
	return file, nil
}

func validateHardwareContinueDescriptor(fd int) error {
	var info syscall.Stat_t
	if fd < 0 || syscall.Fstat(fd, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return errors.New("age helper continue descriptor is not a pipe")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return errors.New("age helper continue descriptor is not read-only")
	}
	syscall.CloseOnExec(fd)
	descriptorFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || descriptorFlags&unix.FD_CLOEXEC == 0 {
		return errors.New("age helper continue descriptor cannot be protected")
	}
	return nil
}

func readHardwareContinue(reader io.Reader) error {
	if reader == nil {
		return errors.New("age helper continue pipe is unavailable")
	}
	var signal [1]byte
	if _, err := io.ReadFull(reader, signal[:]); err != nil || signal[0] != hardwareContinueSignal {
		return errors.New("age helper continue signal is invalid")
	}
	return ensureEOF(reader)
}

func writeHardwareContinue(writer io.Writer) error {
	if writer == nil {
		return errors.New("age helper continue pipe is unavailable")
	}
	return writeFull(writer, []byte{hardwareContinueSignal})
}
