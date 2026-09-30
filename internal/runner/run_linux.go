//go:build linux

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// childCommand re-executes Envrune so the child can drop dumpability before
// exec. The resolved path travels separately from the original argv.
func childCommand(path string, command []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := append([]string{"__envrune_exec", "--", path}, command...)
	return exec.Command(self, args...), nil
}

// ChildExec receives "--", the resolved executable path, then the argv.
func ChildExec(args []string) int {
	if len(args) < 3 || args[0] != "--" {
		return 2
	}
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	err := syscall.Exec(args[1], args[2:], os.Environ())
	fmt.Fprintf(os.Stderr, "envrune: cannot execute %s: %v\n", args[2], err)
	return 126
}
