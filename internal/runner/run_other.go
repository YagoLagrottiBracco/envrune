//go:build !linux

package runner

import "os/exec"

func configureChild(_ *exec.Cmd) {}
func childCommand(command []string) (*exec.Cmd, error) { return exec.Command(command[0], command[1:]...), nil }
func ChildExec(_ []string) int { return 2 }
