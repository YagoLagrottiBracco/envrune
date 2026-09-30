//go:build darwin

package keychain

import (
	"bytes"
	"errors"
	"os/exec"
)

// The secret is passed to `security -i` on standard input, never as an
// argument, so it does not show up in the process list.
func set(account string, secret []byte) error {
	if _, err := exec.LookPath("security"); err != nil {
		return ErrUnavailable
	}
	script := []byte("add-generic-password -U -s " + service + " -a " + account + " -l \"EnvRune vault key\" -w ")
	script = append(script, secret...)
	script = append(script, '\n')
	defer wipe(script)
	cmd := exec.Command("security", "-i")
	cmd.Stdin = bytes.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil || stderr.Len() > 0 {
		return errors.New("the macOS keychain refused the key")
	}
	return nil
}

func get(account string) ([]byte, error) {
	if _, err := exec.LookPath("security"); err != nil {
		return nil, ErrUnavailable
	}
	out, err := exec.Command("security", "find-generic-password", "-s", service, "-a", account, "-w").Output()
	if err != nil {
		return nil, ErrNotFound
	}
	return out, nil
}

func remove(account string) error {
	if _, err := exec.LookPath("security"); err != nil {
		return ErrUnavailable
	}
	_ = exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
	return nil
}
