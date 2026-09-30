//go:build !unix && !windows

package runner

import (
	"os"
	"os/exec"
)

func ownGroup(*exec.Cmd) {}

func stopTree(process *os.Process, _ bool) { _ = process.Kill() }
