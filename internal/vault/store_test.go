package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	crypto "github.com/YagoLagrottiBracco/envrune/internal/crypto"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/filelock"
)

func TestVaultRoundTripKeepsSentinelOutOfCiphertext(t *testing.T) {
	const sentinel = "enrune-test-secret-DO-NOT-LEAK"
	p := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("correct horse battery staple")
	if _, err := Create(p, password, crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	v, err := Open(p, password)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := domain.ParseReference("openai.personal")
	if err := v.Update(func(v *Opened) error { return v.Put(r, []byte(sentinel), time.Now()) }); err != nil {
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
	if _, err := Create(p, []byte("correct"), crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, []byte("wrong")); !errors.Is(err, ErrCannotUnlock) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestCannotUnlockDoesNotDistinguishFailureKinds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("correct")
	if _, err := Create(p, password, crypto.DefaultKDFParams(1)); err != nil {
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
	if _, err := Create(p, []byte("correct"), crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(p, []byte("other"), crypto.DefaultKDFParams(1)); !errors.Is(err, ErrAlreadyExists) {
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

func TestConcurrentSessionsMergeInsteadOfOverwriting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("correct")
	if _, err := Create(p, password, crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	first, err := Open(p, password)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(p, password)
	if err != nil {
		t.Fatalf("second session could not open the vault: %v", err)
	}
	defer second.Close()
	a, _ := domain.ParseReference("first.secret")
	b, _ := domain.ParseReference("second.secret")
	if err := first.Update(func(v *Opened) error { return v.Put(a, []byte("a"), time.Now()) }); err != nil {
		t.Fatal(err)
	}
	if err := second.Update(func(v *Opened) error { return v.Put(b, []byte("b"), time.Now()) }); err != nil {
		t.Fatal(err)
	}
	if err := first.Refresh(); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []domain.Reference{a, b} {
		if _, ok := first.Value(ref); !ok {
			t.Fatalf("%s was lost by a concurrent write", ref)
		}
	}
}

func TestHeldLockReportsBusyWithOwnerPID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	if _, err := Create(p, []byte("correct"), crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	previous := filelock.Wait
	filelock.Wait = 50 * time.Millisecond
	defer func() { filelock.Wait = previous }()
	held, err := acquireLock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_, err = Open(p, []byte("correct"))
	var busy *BusyError
	if !errors.As(err, &busy) || !errors.Is(err, ErrBusy) || busy.PID != os.Getpid() {
		t.Fatalf("Open() error = %v, want BusyError for PID %d", err, os.Getpid())
	}
	if errors.Is(err, ErrCannotUnlock) {
		t.Fatal("a busy vault must not look like a wrong password")
	}
}

func TestVersion1VaultIsUpgradedWithItsSecrets(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("correct")
	params := crypto.DefaultKDFParams(1)
	salt, nonce := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 24)
	key, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		t.Fatal(err)
	}
	header := Header{Params: params, Salt: salt, Nonce: nonce}.MarshalBinary()
	sealed, err := crypto.Seal(key, nonce, []byte(`{"version":1,"secrets":{"old.secret":"dmFsdWU="},"projects":[]}`), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(header, sealed...), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := Open(p, password)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	raw, _ := os.ReadFile(p)
	if !isV2(raw) {
		t.Fatal("vault was not upgraded to version 2")
	}
	v, err = Open(p, password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if value, ok := v.Value("old.secret"); !ok || string(value) != "value" {
		t.Fatalf("upgraded value = %q, %v", value, ok)
	}
}

func TestRecoveryKeyOpensVaultAndResetsPassword(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	recovery, err := Create(p, []byte("forgotten"), crypto.DefaultKDFParams(1))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRecoveryKey(strings.ToLower(FormatRecoveryKey(recovery)))
	if err != nil || !bytes.Equal(parsed, recovery) {
		t.Fatalf("recovery key round trip failed: %v", err)
	}
	v, err := OpenWithRecovery(p, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Update(func(v *Opened) error { return v.ChangePassword([]byte("new password")) }); err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, err := Open(p, []byte("forgotten")); !errors.Is(err, ErrCannotUnlock) {
		t.Fatalf("old password still works: %v", err)
	}
	v, err = Open(p, []byte("new password"))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, err := OpenWithRecovery(p, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrCannotUnlock) {
		t.Fatalf("wrong recovery key error = %v", err)
	}
}

func TestPutKeepsHistoryAndRollbackSwaps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	if _, err := Create(p, []byte("pw"), crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	v, err := Open(p, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ref, _ := domain.ParseReference("api.key")
	for i := 0; i < maxHistory+3; i++ {
		value := []byte{byte('a' + i)}
		if err := v.Update(func(v *Opened) error { return v.Put(ref, value, time.Now()) }); err != nil {
			t.Fatal(err)
		}
	}
	info, _ := v.Info(ref)
	if len(info.Previous) != maxHistory || info.CreatedAt.IsZero() {
		t.Fatalf("info = %+v", info)
	}
	if err := v.Update(func(v *Opened) error { return v.Rollback(ref, time.Now()) }); err != nil {
		t.Fatal(err)
	}
	if value, _ := v.Value(ref); string(value) != string(rune('a'+maxHistory+1)) {
		t.Fatalf("rollback value = %q", value)
	}
	if err := v.Update(func(v *Opened) error { return v.Rollback(ref, time.Now()) }); err != nil {
		t.Fatal(err)
	}
	if value, _ := v.Value(ref); string(value) != string(rune('a'+maxHistory+2)) {
		t.Fatalf("second rollback value = %q", value)
	}
}

func TestKeyOpensVaultWithoutPassword(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	if _, err := Create(p, []byte("pw"), crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	v, err := Open(p, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	key := v.Key()
	v.Close()
	again, err := OpenWithKey(p, key)
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
}
