//go:build !unix && !windows

package runner

import (
	"os"
	"os/exec"
)

func ownGroup(*exec.Cmd) {}

type tree struct{}

func track(*os.Process) tree { return tree{} }

func stopTree(process *os.Process, _ bool, _ *tree) { _ = process.Kill() }
