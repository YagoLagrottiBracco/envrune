//go:build unix

package runner

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func ownGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// tree needs no state on Unix: the process group outlives its leader.
type tree struct{}

func track(*os.Process) tree { return tree{} }

// stopTree sends SIGTERM, then SIGKILL after a grace period, to the child's
// process group when it has one.
func stopTree(process *os.Process, group bool, _ *tree) {
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
