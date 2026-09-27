package crypto

import (
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var ErrInvalidInput = errors.New("invalid cryptographic input")

func DeriveKey(password, salt []byte, params KDFParams) ([]byte, error) {
	if len(salt) != 32 || !params.Valid() {
		return nil, ErrInvalidInput
	}
	return argon2.IDKey(password, salt, params.Time, params.MemoryKiB, params.Threads, params.KeyLength), nil
}

func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidInput
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidInput
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
