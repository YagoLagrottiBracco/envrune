//go:build linux

package runner

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func configureChild(_ *exec.Cmd) {}

func childCommand(command []string) (*exec.Cmd, error) {
	self, err := os.Executable(); if err != nil { return nil, err }
	args := append([]string{"__envrune_exec", "--"}, command...)
	return exec.Command(self, args...), nil
}

func ChildExec(args []string) int {
	if len(args) < 3 || args[0] != "--" { return 2 }
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	if err := syscall.Exec(args[1], args[1:], os.Environ()); err != nil { return 1 }
	return 1
}
