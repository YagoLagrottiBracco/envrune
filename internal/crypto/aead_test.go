package crypto

import (
	"bytes"
	"testing"
)

func TestOpenRejectsModifiedAAD(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	nonce := bytes.Repeat([]byte{2}, 24)
	ciphertext, err := Seal(key, nonce, []byte("payload"), []byte("header-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, nonce, ciphertext, []byte("header-b")); err == nil {
		t.Fatal("Open() accepted modified AAD")
	}
}

func TestDeriveKeyRejectsInvalidSalt(t *testing.T) {
	if _, err := DeriveKey([]byte("password"), []byte("short"), DefaultKDFParams(1)); err == nil {
		t.Fatal("DeriveKey() accepted invalid salt")
	}
}
