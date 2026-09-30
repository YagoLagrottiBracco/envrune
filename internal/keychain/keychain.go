// Package keychain stores the vault's data key in the operating system's
// credential store: Windows Credential Manager, the macOS Keychain, or the
// Secret Service (libsecret) on Linux. The store is unlocked by the user's
// login, so terminals open without the master password.
package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var (
	ErrUnavailable = errors.New("no system keychain is available")
	ErrNotFound    = errors.New("no key is stored in the system keychain")
)

const service = "envrune"

// Account names the entry for the vault at vaultPath without putting the
// path itself in the credential store.
func Account(vaultPath string) string {
	sum := sha256.Sum256([]byte(vaultPath))
	return "vault-" + hex.EncodeToString(sum[:8])
}

// Set stores key under account, replacing any earlier entry.
func Set(account string, key []byte) error {
	encoded := []byte(hex.EncodeToString(key))
	defer wipe(encoded)
	return set(account, encoded)
}

// Get returns the key stored under account.
func Get(account string) ([]byte, error) {
	encoded, err := get(account)
	if err != nil {
		return nil, err
	}
	defer wipe(encoded)
	trimmed := trimSpace(encoded)
	key := make([]byte, hex.DecodedLen(len(trimmed)))
	if n, err := hex.Decode(key, trimmed); err != nil || n != 32 {
		wipe(key)
		return nil, ErrNotFound
	}
	return key, nil
}

// Delete removes the entry under account. A missing entry is not an error.
func Delete(account string) error { return remove(account) }

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
