package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	crypto "github.com/envrune/envrune/internal/crypto"
	"github.com/envrune/envrune/internal/domain"
)

type payload struct {
	Version  uint8             `json:"version"`
	Secrets  map[string][]byte `json:"secrets"`
	Projects []string          `json:"projects"`
}

const maxVaultBytes = 16 << 20

// Opened is an unlocked vault held in memory. It never keeps the file lock:
// reads and writes lock the file only while they touch it, and every write
// first merges in changes other processes committed since this one last read.
// The header nonce changes on every write, so it doubles as the version.
type Opened struct {
	path   string
	header Header
	key    []byte
	data   payload
}

func Create(path string, password []byte, params crypto.KDFParams) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lock, err := acquireLock(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := os.Stat(path); err == nil {
		return ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return err
	}
	v := &Opened{path: path, header: Header{Params: params, Salt: salt}, key: key, data: payload{Version: 1, Secrets: map[string][]byte{}, Projects: []string{}}}
	defer v.Close()
	return v.write()
}

func Open(path string, password []byte) (*Opened, error) {
	raw, err := readLocked(path)
	if err != nil {
		return nil, err
	}
	h, err := ParseHeader(raw[:headerSize])
	if err != nil {
		return nil, ErrCannotUnlock
	}
	key, err := crypto.DeriveKey(password, h.Salt, h.Params)
	if err != nil {
		return nil, ErrCannotUnlock
	}
	data, err := decode(key, h, raw)
	if err != nil {
		wipe(key)
		return nil, err
	}
	return &Opened{path: path, header: h, key: key, data: data}, nil
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

func (v *Opened) RegisterProject(path string) {
	for _, known := range v.data.Projects {
		if known == path {
			return
		}
	}
	v.data.Projects = append(v.data.Projects, path)
}

func (v *Opened) Projects() []string { return append([]string(nil), v.data.Projects...) }

func (v *Opened) Put(ref domain.Reference, value []byte, _ time.Time) error {
	v.data.Secrets[ref.String()] = append([]byte(nil), value...)
	return nil
}

func (v *Opened) Value(ref domain.Reference) ([]byte, bool) {
	value, ok := v.data.Secrets[ref.String()]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

func (v *Opened) References() []domain.Reference {
	refs := make([]domain.Reference, 0, len(v.data.Secrets))
	for raw := range v.data.Secrets {
		if ref, err := domain.ParseReference(raw); err == nil {
			refs = append(refs, ref)
		}
	}
	return refs
}

func (v *Opened) Close() {
	if v == nil {
		return
	}
	wipe(v.key)
	v.key = nil
	v.wipeData()
	v.data.Secrets = nil
	v.data.Projects = nil
}

func (v *Opened) wipeData() {
	for _, value := range v.data.Secrets {
		wipe(value)
	}
	clear(v.data.Secrets)
}

// reload replaces the in-memory state when raw holds a newer version.
func (v *Opened) reload(raw []byte) error {
	h, err := ParseHeader(raw[:headerSize])
	if err != nil {
		return ErrCannotUnlock
	}
	if bytes.Equal(h.Nonce, v.header.Nonce) {
		return nil
	}
	if !bytes.Equal(h.Salt, v.header.Salt) || h.Params != v.header.Params {
		return ErrReplaced
	}
	data, err := decode(v.key, h, raw)
	if err != nil {
		return err
	}
	v.wipeData()
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
	nonce := make([]byte, 24)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	header := Header{Params: v.header.Params, Salt: v.header.Salt, Nonce: nonce}
	headerRaw := header.MarshalBinary()
	cipher, err := crypto.Seal(v.key, nonce, plain, headerRaw)
	if err != nil {
		return err
	}
	if len(headerRaw)+len(cipher) > maxVaultBytes {
		return ErrCannotUnlock
	}
	tmp, err := os.CreateTemp(filepath.Dir(v.path), ".vault-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(append(headerRaw, cipher...)); err != nil {
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
	if err = os.Rename(name, v.path); err != nil {
		return err
	}
	v.header = header
	return syncParent(filepath.Dir(v.path))
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

func decode(key []byte, h Header, raw []byte) (payload, error) {
	plain, err := crypto.Open(key, h.Nonce, raw[headerSize:], raw[:headerSize])
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
	return data, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
