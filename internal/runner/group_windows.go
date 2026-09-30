//go:build windows

package runner

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// tree is a job object holding the child and everything it starts. Windows
// has no process groups that outlive their leader, so this is how Stop still
// reaches a server that npm started after npm itself has exited. The job
// kills its processes when its last handle closes, including when Envrune
// itself dies.
type tree struct {
	job     windows.Handle
	stopped bool
}

// track puts a started child in a new job object. A process the child
// starts in the instant before this runs escapes the job. When the job
// cannot be created, stopTree falls back to taskkill.
func track(process *os.Process) tree {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return tree{}
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return tree{}
	}
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return tree{}
	}
	defer windows.CloseHandle(handle)
	if windows.AssignProcessToJobObject(job, handle) != nil {
		_ = windows.CloseHandle(job)
		return tree{}
	}
	return tree{job: job}
}

// stopTree ends the child and every process it started. npm, for example,
// runs node through cmd.exe, so ending only the direct child would leave the
// server running.
func stopTree(process *os.Process, _ bool, t *tree) {
	if t.stopped {
		return
	}
	t.stopped = true
	if t.job != 0 {
		_ = windows.TerminateJobObject(t.job, 1)
		_ = windows.CloseHandle(t.job)
		t.job = 0
		return
	}
	kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(process.Pid))
	kill.Stdout, kill.Stderr = io.Discard, io.Discard
	if kill.Run() != nil {
		_ = process.Kill()
	}
}
