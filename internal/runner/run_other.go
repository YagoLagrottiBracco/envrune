//go:build !linux

package runner

import "os/exec"

func childCommand(path string, command []string) (*exec.Cmd, error) {
	cmd := exec.Command(path, command[1:]...)
	cmd.Args[0] = command[0]
	return cmd, nil
}
