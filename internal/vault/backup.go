package vault

import (
	"os"
	"path/filepath"

	crypto "github.com/YagoLagrottiBracco/envrune/internal/crypto"
)

// Backup copies the encrypted vault file to dest, which must not exist. The
// copy stays encrypted, so it is as safe to store as the vault itself.
func Backup(path, dest string) error {
	raw, err := readLocked(path)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// Verify checks that backupPath is a vault that opens with password, or with
// recovery when password is nil, without changing the file.
func Verify(backupPath string, password, recovery []byte) error {
	raw, err := readRaw(backupPath)
	if err != nil {
		return err
	}
	if !isV2(raw) {
		if password == nil {
			return ErrNoRecovery
		}
		h, err := ParseHeader(raw[:headerSize])
		if err != nil {
			return err
		}
		key, err := crypto.DeriveKey(password, h.Salt, h.Params)
		if err != nil {
			return ErrCannotUnlock
		}
		defer wipe(key)
		data, err := decode(key, h.Nonce, raw[headerSize:], raw[:headerSize])
		data.wipe()
		return err
	}
	h, err := parseHeaderV2(raw)
	if err != nil {
		return err
	}
	var dek []byte
	if password != nil {
		kek, err := crypto.DeriveKey(password, h.Salt, h.Params)
		if err != nil {
			return ErrCannotUnlock
		}
		dek, err = h.unwrapPassword(kek)
		wipe(kek)
		if err != nil {
			return err
		}
	} else if dek, err = h.unwrapRecovery(recovery); err != nil {
		return err
	}
	defer wipe(dek)
	data, err := decode(dek, h.Nonce, raw[header2Size:], raw[:header2Size])
	data.wipe()
	return err
}

// Restore replaces the vault at path with the file at backupPath.
func Restore(path, backupPath string) error {
	raw, err := readRaw(backupPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0700); err != nil {
		return err
	}
	lock, err := acquireLock(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	return writeFileAtomic(path, raw)
}

func dirOf(path string) string { return filepath.Dir(path) }
