package main

import (
	"context"
	"os"
	"runtime"

	"github.com/mofelee/yubitouch/internal/agehelper"
	"github.com/mofelee/yubitouch/internal/ageprobe"
	"github.com/mofelee/yubitouch/internal/command"
	"github.com/mofelee/yubitouch/internal/pin"
)

func main() {
	runtime.LockOSThread()
	home, _ := os.UserHomeDir()
	if handled, code := ageprobe.RunInternalFromEnvironment(context.Background(), os.Stdin, os.Stdout, os.Getenv, home); handled {
		os.Exit(code)
	}
	if handled, code := agehelper.RunInternalFromEnvironment(context.Background(), os.Stdin, os.Stdout, os.Getenv, home); handled {
		os.Exit(code)
	}
	runtime.UnlockOSThread()
	if os.Getenv("YUBITOUCH_INTERNAL_ASKPASS") == "1" {
		runtime.LockOSThread()
		prompt := ""
		if len(os.Args) > 1 {
			prompt = os.Args[1]
		}
		os.Exit(pin.RunAskPass(context.Background(), prompt, os.Stdout, os.Stderr, home, os.Getenv))
	}
	os.Exit(command.Run(os.Args[1:], os.Stdout, os.Stderr, command.OS()))
}
