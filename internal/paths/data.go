// Package paths resolves filesystem locations used by Envrune.
package paths

import "path"

// VaultPath returns the XDG data location for Envrune's encrypted vault.
func VaultPath(getenv func(string) string, homeDir func() (string, error)) (string, error) {
	base := getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := homeDir()
		if err != nil {
			return "", err
		}
		base = path.Join(home, ".local", "share")
	}
	return path.Join(base, "envrune", "vault.ev1"), nil
}
