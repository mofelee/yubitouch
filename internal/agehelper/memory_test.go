package agehelper

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

const coreDumpLimitChildEnvironment = "YUBITOUCH_TEST_CORE_DUMP_LIMIT_CHILD"

func TestDisableCoreDumpsSetsZeroLimit(t *testing.T) {
	if os.Getenv(coreDumpLimitChildEnvironment) == "1" {
		if err := disableCoreDumps(); err != nil {
			t.Fatal(err)
		}
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
			t.Fatal(err)
		}
		if limit.Cur != 0 || limit.Max != 0 {
			t.Fatalf("core dump limit = current %d max %d, want both zero", limit.Cur, limit.Max)
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestDisableCoreDumpsSetsZeroLimit$")
	cmd.Env = append(os.Environ(), coreDumpLimitChildEnvironment+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("core dump limit child failed: %v\n%s", err, output)
	}
}
