//go:build windows

package keychain

import (
	"bytes"
	"errors"
	"testing"
)

func TestCredentialManagerRoundTrip(t *testing.T) {
	account := "test-" + Account(t.Name())
	key := bytes.Repeat([]byte{0xab}, 32)
	if err := Set(account, key); err != nil {
		t.Skipf("Credential Manager unavailable: %v", err)
	}
	defer Delete(account)
	got, err := Get(account)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("Get() = %x, %v", got, err)
	}
	if err := Delete(account); err != nil {
		t.Fatal(err)
	}
	if _, err := Get(account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after Delete = %v", err)
	}
}
