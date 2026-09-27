package app

import (
	"errors"
	"runtime"
	"sort"
	"time"

	crypto "github.com/envrune/envrune/internal/crypto"
	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/vault"
)

var ErrPasswordConfirmation = errors.New("master password confirmation does not match")

type VaultService struct{}

func (VaultService) Init(path string, password, confirmation []byte) error {
	if string(password) != string(confirmation) {
		return ErrPasswordConfirmation
	}
	return vault.Create(path, password, crypto.DefaultKDFParams(runtime.NumCPU()))
}

func (VaultService) Set(path string, password []byte, rawReference string, value []byte) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	v, err := vault.Open(path, password)
	if err != nil {
		return err
	}
	defer v.Close()
	if err := v.Put(ref, value, time.Now()); err != nil {
		return err
	}
	return v.Commit()
}

func (VaultService) List(path string, password []byte) ([]string, error) {
	v, err := vault.Open(path, password)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	refs := v.References()
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.String()
	}
	sort.Strings(out)
	return out, nil
}
