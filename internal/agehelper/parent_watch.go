package agehelper

import "github.com/mofelee/yubitouch/internal/parentwatch"

const parentWatchEnvironment = "YUBITOUCH_INTERNAL_AGE_PARENT_FD"

func startParentLifetimeWatch(getenv func(string) string) (func(), error) {
	return parentwatch.Start(getenv, parentWatchEnvironment, helperFailureExitCode)
}
