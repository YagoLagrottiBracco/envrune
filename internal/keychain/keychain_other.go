//go:build !windows && !darwin

package keychain

import (
	"bytes"
	"os/exec"
)

// Linux and other Unix systems use the Secret Service through secret-tool
// (package libsecret-tools on Debian and Ubuntu). The secret travels on
// standard input.
func set(account string, secret []byte) error {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return ErrUnavailable
	}
	cmd := exec.Command("secret-tool", "store", "--label=EnvRune vault key", "service", service, "account", account)
	cmd.Stdin = bytes.NewReader(secret)
	if err := cmd.Run(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func get(account string) ([]byte, error) {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return nil, ErrUnavailable
	}
	out, err := exec.Command("secret-tool", "lookup", "service", service, "account", account).Output()
	if err != nil || len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func remove(account string) error {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return ErrUnavailable
	}
	_ = exec.Command("secret-tool", "clear", "service", service, "account", account).Run()
	return nil
}
