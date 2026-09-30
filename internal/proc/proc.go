// Package proc starts helper processes that outlive the command that
// started them, such as the unlock agent and the clipboard cleaner.
package proc

import (
	"io"
	"os"
	"os/exec"
)

// StartDetached runs this executable with args in the background, detached
// from the terminal, and writes input to its standard input before closing it.
func StartDetached(args []string, input []byte) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, args...)
	detach(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	_, werr := stdin.Write(input)
	cerr := stdin.Close()
	_ = cmd.Process.Release()
	if werr != nil {
		return werr
	}
	return cerr
}

// Helper runs fn and exits when this process was started as the helper
// named name, which Envrune passes as the first argument when it starts
// itself again. Packages call it from init, so any binary that links them,
// test binaries included, turns into the helper before running anything
// else instead of starting over as the whole program.
func Helper(name string, fn func(args []string) int) {
	if len(os.Args) > 1 && os.Args[1] == name {
		os.Exit(fn(os.Args[2:]))
	}
}
