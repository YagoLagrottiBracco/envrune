package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOnboardingCreatesVaultAfterExplicitConfirmation(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("test master password")
	confirmation := []byte("test master password")
	var stdout, stderr bytes.Buffer
	secrets := [][]byte{password, confirmation}

	code := Onboarding{
		VaultPath: vaultPath,
		Stdout:    &stdout,
		Stderr:    &stderr,
		ReadChoice: func(string) (string, error) {
			return "yes", nil
		},
		ReadSecret: func(string) ([]byte, error) {
			value := secrets[0]
			secrets = secrets[1:]
			return value, nil
		},
	}.Run()

	if code != 0 {
		t.Fatalf("Run() = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("vault was not created: %v", err)
	}
	if !strings.Contains(stderr.String(), "Vault initialized. Run `envrune shell` to begin.") {
		t.Fatalf("expected completion guidance, got %q", stderr.String())
	}
	if !isWiped(password) {
		t.Fatal("master password was not wiped")
	}
	if !isWiped(confirmation) {
		t.Fatal("master password confirmation was not wiped")
	}
}

func isWiped(value []byte) bool {
	for _, byte := range value {
		if byte != 0 {
			return false
		}
	}
	return true
}

func TestOnboardingDoesNotCreateVaultWhenDeclined(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.ev1")
	var stdout, stderr bytes.Buffer

	code := Onboarding{
		VaultPath: vaultPath,
		Stdout:    &stdout,
		Stderr:    &stderr,
		ReadChoice: func(string) (string, error) {
			return "n", nil
		},
		ReadSecret: func(string) ([]byte, error) {
			t.Fatal("password input should not be requested when initialization is declined")
			return nil, nil
		},
	}.Run()

	if code != 0 {
		t.Fatalf("Run() = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(vaultPath); !os.IsNotExist(err) {
		t.Fatalf("vault exists after declined initialization: %v", err)
	}
	if !strings.Contains(stderr.String(), "Initialization cancelled.") {
		t.Fatalf("expected cancellation feedback, got %q", stderr.String())
	}
}

func TestOnboardingGuidesExistingVaultWithoutPromptingForPassword(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.ev1")
	if err := os.WriteFile(vaultPath, []byte("existing encrypted vault"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	code := Onboarding{
		VaultPath: vaultPath,
		Stdout:    &stdout,
		Stderr:    &stderr,
		ReadChoice: func(string) (string, error) {
			t.Fatal("setup choice should not be requested for an existing vault")
			return "", nil
		},
		ReadSecret: func(string) ([]byte, error) {
			t.Fatal("password input should not be requested for an existing vault")
			return nil, nil
		},
	}.Run()

	if code != 0 {
		t.Fatalf("Run() = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Vault is ready. Run `envrune shell` to begin.") {
		t.Fatalf("expected existing-vault guidance, got %q", stderr.String())
	}
}
