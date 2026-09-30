//go:build !unix && !windows

package proc

import "os/exec"

func detach(*exec.Cmd) {}
