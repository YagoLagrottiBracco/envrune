//go:build windows

package runner

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows"
)

func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// stopTree ends the child and every process it started. npm, for example,
// runs node through cmd.exe, so ending only the direct child would leave the
// server running.
func stopTree(process *os.Process, _ bool) {
	kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(process.Pid))
	kill.Stdout, kill.Stderr = io.Discard, io.Discard
	if kill.Run() != nil {
		_ = process.Kill()
	}
}
