//go:build !linux

package runner

import "os/exec"

func configureChild(_ *exec.Cmd) {}
