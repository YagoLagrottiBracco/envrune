package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	crypto "github.com/envrune/envrune/internal/crypto"
	"github.com/envrune/envrune/internal/domain"
)

func TestVaultRoundTripKeepsSentinelOutOfCiphertext(t *testing.T) {
	const sentinel = "enrune-test-secret-DO-NOT-LEAK"
	p := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("correct horse battery staple")
	if err := Create(p, password, crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	v, err := Open(p, password)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := domain.ParseReference("openai.personal")
	if err := v.Put(r, []byte(sentinel), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(sentinel)) {
		t.Fatal("plaintext leaked")
	}
}

func TestWrongPasswordReturnsCannotUnlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	if err := Create(p, []byte("correct"), crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, []byte("wrong")); !errors.Is(err, ErrCannotUnlock) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestCannotUnlockDoesNotDistinguishFailureKinds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("correct")
	if err := Create(p, password, crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func([]byte){
		func(b []byte) { b[0] ^= 1 },
		func(b []byte) { b[len(b)-1] ^= 1 },
	} {
		mutated := append([]byte(nil), raw...)
		mutation(mutated)
		if err := os.WriteFile(p, mutated, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(p, password); !errors.Is(err, ErrCannotUnlock) {
			t.Fatalf("Open() error = %v, want ErrCannotUnlock", err)
		}
	}
}

func TestExistingVaultIsNeverOverwritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	if err := Create(p, []byte("correct"), crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Create(p, []byte("other"), crypto.DefaultKDFParams(1)); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Create() error = %v, want ErrAlreadyExists", err)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing vault was overwritten")
	}
}

func TestOpenRejectsOversizedVault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	if err := os.WriteFile(p, make([]byte, maxVaultBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, []byte("password")); !errors.Is(err, ErrCannotUnlock) {
		t.Fatalf("Open error = %v", err)
	}
}
