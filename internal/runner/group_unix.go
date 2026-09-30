//go:build unix

package runner

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func ownGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// stopTree sends SIGTERM, then SIGKILL after a grace period, to the child's
// process group when it has one.
func stopTree(process *os.Process, group bool) {
	target := process.Pid
	if group {
		target = -process.Pid
	}
	_ = syscall.Kill(target, syscall.SIGTERM)
	go func() {
		time.Sleep(5 * time.Second)
		_ = syscall.Kill(target, syscall.SIGKILL)
	}()
}
