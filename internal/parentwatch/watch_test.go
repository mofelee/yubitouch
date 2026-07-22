package parentwatch

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLifetimeWatchTerminatesOnEOF(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	terminated := make(chan struct{})
	watch := &lifetimeWatch{
		file: reader,
		terminate: func() {
			close(terminated)
		},
		done: make(chan struct{}),
	}
	go watch.run()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-terminated:
	case <-time.After(3 * time.Second):
		t.Fatal("parent-lifetime watch did not react to EOF")
	}
	<-watch.done
	_ = reader.Close()
}

func TestLifetimeWatchCanBeDisarmed(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	terminated := make(chan struct{})
	watch := &lifetimeWatch{
		file: reader,
		terminate: func() {
			close(terminated)
		},
		done: make(chan struct{}),
	}
	go watch.run()
	disarmed := make(chan struct{})
	go func() {
		watch.disarm()
		close(disarmed)
	}()
	select {
	case <-disarmed:
	case <-time.After(3 * time.Second):
		t.Fatal("disarming the parent-lifetime watch blocked")
	}
	select {
	case <-terminated:
		t.Fatal("disarming the parent-lifetime watch terminated the helper")
	default:
	}
	watch.disarm()
}

func TestAttachRequiresUnusedDescriptorThree(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	watchEnd, parentAlive, err := Attach(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer watchEnd.Close()
	defer parentAlive.Close()
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != watchEnd {
		t.Fatal("parent watch was not assigned to descriptor 3")
	}
	if _, _, err := Attach(cmd); err == nil {
		t.Fatal("parent watch accepted preexisting extra files")
	}
}

func TestEnvironmentValidation(t *testing.T) {
	if got := Environment("YUBITOUCH_INTERNAL_PARENT_FD"); got != "YUBITOUCH_INTERNAL_PARENT_FD=3" {
		t.Fatalf("environment entry = %q", got)
	}
	for _, invalid := range []string{"", "BAD=NAME", "BAD\x00NAME"} {
		if got := Environment(invalid); got != "" {
			t.Fatalf("Environment(%q) = %q", invalid, got)
		}
	}
}

func TestWatchDescriptorMustBeReadEndOfPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := validateWatchDescriptor(int(reader.Fd())); err != nil {
		t.Fatalf("read end rejected: %v", err)
	}
	if err := validateWatchDescriptor(int(writer.Fd())); err == nil {
		t.Fatal("write end accepted as a parent watch")
	}
}
