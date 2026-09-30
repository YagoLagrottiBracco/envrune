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
