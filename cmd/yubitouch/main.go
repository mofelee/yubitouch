package main

import (
	"context"
	"os"
	"runtime"

	"github.com/mofelee/yubitouch/internal/command"
	"github.com/mofelee/yubitouch/internal/pin"
)

func main() {
	if os.Getenv("YUBITOUCH_INTERNAL_ASKPASS") == "1" {
		runtime.LockOSThread()
		prompt := ""
		if len(os.Args) > 1 {
			prompt = os.Args[1]
		}
		home, _ := os.UserHomeDir()
		os.Exit(pin.RunAskPass(context.Background(), prompt, os.Stdout, os.Stderr, home, os.Getenv))
	}
	os.Exit(command.Run(os.Args[1:], os.Stdout, os.Stderr, command.OS()))
}
