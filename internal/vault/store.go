package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	crypto "github.com/YagoLagrottiBracco/envrune/internal/crypto"
)

const maxVaultBytes = 16 << 20

// Opened is an unlocked vault held in memory. It never keeps the file lock:
// reads and writes lock the file only while they touch it, and every write
// first merges in changes other processes committed since this one last read.
// The payload nonce changes on every write, so it doubles as the version.
type Opened struct {
	path   string
	header headerV2
	dek    []byte
	data   payload
}

// Create writes a new vault and returns its recovery key, which is shown to
// the user once and never stored.
func Create(path string, password []byte, params crypto.KDFParams) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if _, err := os.Stat(path); err == nil {
		return nil, ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	salt, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	dek, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	recovery, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	kek, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	h := headerV2{Params: params, Salt: salt}
	if err := h.wrapPassword(kek, dek); err != nil {
		return nil, err
	}
	if err := h.wrapRecovery(recovery, dek); err != nil {
		return nil, err
	}
	v := &Opened{path: path, header: h, dek: dek, data: newPayload()}
	defer v.Close()
	if err := v.write(); err != nil {
		wipe(recovery)
		return nil, err
	}
	return recovery, nil
}

// Open unlocks the vault with the master password. A version 1 vault is
// upgraded to version 2 on the way.
func Open(path string, password []byte) (*Opened, error) {
	raw, err := readLocked(path)
	if err != nil {
		return nil, err
	}
	if !isV2(raw) {
		return openV1(path, password)
	}
	h, err := parseHeaderV2(raw)
	if err != nil {
		return nil, err
	}
	kek, err := crypto.DeriveKey(password, h.Salt, h.Params)
	if err != nil {
		return nil, ErrCannotUnlock
	}
	defer wipe(kek)
	dek, err := h.unwrapPassword(kek)
	if err != nil {
		return nil, err
	}
	return openWithDEK(path, h, dek, raw)
}

// OpenWithKey unlocks the vault with a data key previously taken from an
// opened vault, as the agent and the system keychain do.
func OpenWithKey(path string, key []byte) (*Opened, error) {
	raw, err := readLocked(path)
	if err != nil {
		return nil, err
	}
	h, err := parseHeaderV2(raw)
	if err != nil {
		return nil, err
	}
	return openWithDEK(path, h, append([]byte(nil), key...), raw)
}

// OpenWithRecovery unlocks the vault with its recovery key.
func OpenWithRecovery(path string, recovery []byte) (*Opened, error) {
	raw, err := readLocked(path)
	if err != nil {
		return nil, err
	}
	h, err := parseHeaderV2(raw)
	if err != nil {
		return nil, err
	}
	dek, err := h.unwrapRecovery(recovery)
	if err != nil {
		return nil, err
	}
	return openWithDEK(path, h, dek, raw)
}

func openWithDEK(path string, h headerV2, dek, raw []byte) (*Opened, error) {
	data, err := decode(dek, h.Nonce, raw[header2Size:], raw[:header2Size])
	if err != nil {
		wipe(dek)
		return nil, err
	}
	return &Opened{path: path, header: h, dek: dek, data: data}, nil
}

// openV1 decrypts a version 1 vault and rewrites it as version 2 under a new
// data key wrapped by the same password-derived key.
func openV1(path string, password []byte) (*Opened, error) {
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	raw, err := readRaw(path)
	if err != nil {
		return nil, err
	}
	if isV2(raw) {
		lock.Close()
		return Open(path, password)
	}
	old, err := ParseHeader(raw[:headerSize])
	if err != nil {
		return nil, ErrCannotUnlock
	}
	kek, err := crypto.DeriveKey(password, old.Salt, old.Params)
	if err != nil {
		return nil, ErrCannotUnlock
	}
	defer wipe(kek)
	data, err := decode(kek, old.Nonce, raw[headerSize:], raw[:headerSize])
	if err != nil {
		return nil, err
	}
	dek, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	h := headerV2{Params: old.Params, Salt: old.Salt}
	if err := h.wrapPassword(kek, dek); err != nil {
		return nil, err
	}
	v := &Opened{path: path, header: h, dek: dek, data: data}
	if err := v.write(); err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

// Refresh loads changes that other processes committed since the last read.
func (v *Opened) Refresh() error {
	raw, err := readLocked(v.path)
	if err != nil {
		return err
	}
	return v.reload(raw)
}

// Update applies change to the latest on-disk state and writes the result
// while holding the lock, so concurrent sessions never overwrite each other.
func (v *Opened) Update(change func(*Opened) error) error {
	lock, err := acquireLock(v.path)
	if err != nil {
		return err
	}
	defer lock.Close()
	raw, err := readRaw(v.path)
	if err != nil {
		return err
	}
	if err := v.reload(raw); err != nil {
		return err
	}
	if err := change(v); err != nil {
		v.header.Nonce = nil // force the next read to discard partial changes
		return err
	}
	if err := v.write(); err != nil {
		v.header.Nonce = nil
		return err
	}
	return nil
}

// Key returns a copy of the data key for the agent or the system keychain.
func (v *Opened) Key() []byte { return append([]byte(nil), v.dek...) }

// Path returns the vault file location.
func (v *Opened) Path() string { return v.path }

// ChangePassword re-wraps the data key for a new master password. Call it
// inside Update. Existing agent and keychain entries stay valid.
func (v *Opened) ChangePassword(password []byte) error {
	salt, err := randomBytes(32)
	if err != nil {
		return err
	}
	kek, err := crypto.DeriveKey(password, salt, v.header.Params)
	if err != nil {
		return err
	}
	defer wipe(kek)
	h := v.header
	h.Salt = salt
	if err := h.wrapPassword(kek, v.dek); err != nil {
		return err
	}
	v.header = h
	return nil
}

// ResetRecovery wraps the data key under a new recovery key and returns it.
// Any earlier recovery key stops working. Call it inside Update.
func (v *Opened) ResetRecovery() ([]byte, error) {
	recovery, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	h := v.header
	if err := h.wrapRecovery(recovery, v.dek); err != nil {
		return nil, err
	}
	v.header = h
	return recovery, nil
}

func (v *Opened) HasRecovery() bool { return v.header.HasRecovery }

func (v *Opened) Close() {
	if v == nil {
		return
	}
	wipe(v.dek)
	v.dek = nil
	v.data.wipe()
	v.data = payload{}
}

// reload replaces the in-memory state when raw holds a newer version.
func (v *Opened) reload(raw []byte) error {
	if !isV2(raw) {
		return ErrReplaced
	}
	h, err := parseHeaderV2(raw)
	if err != nil {
		return err
	}
	if bytes.Equal(h.Nonce, v.header.Nonce) {
		return nil
	}
	data, err := decode(v.dek, h.Nonce, raw[header2Size:], raw[:header2Size])
	if err != nil {
		return ErrReplaced
	}
	v.data.wipe()
	v.header, v.data = h, data
	return nil
}

// write seals the current state under a fresh nonce. The caller holds the lock.
func (v *Opened) write() error {
	plain, err := json.Marshal(v.data)
	if err != nil {
		return err
	}
	defer wipe(plain)
	nonce, err := randomBytes(24)
	if err != nil {
		return err
	}
	header := v.header
	header.Nonce = nonce
	headerRaw := header.marshal()
	cipher, err := crypto.Seal(v.dek, nonce, plain, headerRaw)
	if err != nil {
		return err
	}
	if len(headerRaw)+len(cipher) > maxVaultBytes {
		return ErrTooLarge
	}
	if err := writeFileAtomic(v.path, append(headerRaw, cipher...)); err != nil {
		return err
	}
	v.header = header
	return nil
}

func writeFileAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncParent(filepath.Dir(path))
}

func readLocked(path string) ([]byte, error) {
	lock, err := acquireLock(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return readRaw(path)
}

func readRaw(path string) ([]byte, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, ErrCannotUnlock
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxVaultBytes+1))
	if err != nil || len(raw) > maxVaultBytes || len(raw) < headerSize {
		return nil, ErrCannotUnlock
	}
	return raw, nil
}

func decode(key, nonce, ciphertext, aad []byte) (payload, error) {
	plain, err := crypto.Open(key, nonce, ciphertext, aad)
	if err != nil {
		return payload{}, ErrCannotUnlock
	}
	defer wipe(plain)
	var data payload
	if json.Unmarshal(plain, &data) != nil || data.Version != 1 || data.Secrets == nil {
		return payload{}, ErrCannotUnlock
	}
	if data.Projects == nil {
		data.Projects = []string{}
	}
	if data.Meta == nil {
		data.Meta = map[string]*SecretMeta{}
	}
	return data, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
