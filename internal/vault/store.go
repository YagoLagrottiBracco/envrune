package vault

import (
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
	Version uint8             `json:"version"`
	Secrets map[string][]byte `json:"secrets"`
}
type Opened struct {
	path   string
	header Header
	key    []byte
	data   payload
}

func Create(path string, password []byte, params crypto.KDFParams) error {
	if _, err := os.Stat(path); err == nil {
		return ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	salt, nonce := make([]byte, 32), make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	key, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return err
	}
	v := &Opened{path: path, header: Header{Params: params, Salt: salt, Nonce: nonce}, key: key, data: payload{Version: 1, Secrets: map[string][]byte{}}}
	return v.Commit()
}

func Open(path string, password []byte) (*Opened, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, ErrCannotUnlock
	}
	if len(raw) < headerSize {
		return nil, ErrCannotUnlock
	}
	h, err := ParseHeader(raw[:headerSize])
	if err != nil {
		return nil, ErrCannotUnlock
	}
	key, err := crypto.DeriveKey(password, h.Salt, h.Params)
	if err != nil {
		return nil, ErrCannotUnlock
	}
	plain, err := crypto.Open(key, h.Nonce, raw[headerSize:], raw[:headerSize])
	if err != nil {
		return nil, ErrCannotUnlock
	}
	var data payload
	if json.Unmarshal(plain, &data) != nil || data.Version != 1 || data.Secrets == nil {
		return nil, ErrCannotUnlock
	}
	return &Opened{path: path, header: h, key: key, data: data}, nil
}

func (v *Opened) Put(ref domain.Reference, value []byte, _ time.Time) error {
	v.data.Secrets[ref.String()] = append([]byte(nil), value...)
	return nil
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
func (v *Opened) Commit() error {
	plain, err := json.Marshal(v.data)
	if err != nil {
		return err
	}
	nonce := make([]byte, 24)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	v.header.Nonce = nonce
	header := v.header.MarshalBinary()
	cipher, err := crypto.Seal(v.key, nonce, plain, header)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(v.path), ".vault-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err = tmp.Write(append(header, cipher...)); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, v.path)
}
func (v *Opened) Close() {
	for i := range v.key {
		v.key[i] = 0
	}
}
