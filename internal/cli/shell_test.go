package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/envrune/envrune/internal/app"
)

func TestShellReadsMasterPasswordOnceAndClosesSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	if err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	reads := 0
	var out, errOut bytes.Buffer
	shell := Shell{
		Input:  strings.NewReader("list\nexit\n"),
		Stdout: &out,
		Stderr: &errOut,
		ReadSecret: func(label string) ([]byte, error) {
			reads++
			if label != "Master password" {
				t.Fatalf("unexpected secret prompt: %s", label)
			}
			return append([]byte(nil), password...), nil
		},
		OpenSession: func(got []byte) (*app.Session, error) { return app.OpenSession(path, got) },
	}

	if code := shell.Run(); code != 0 {
		t.Fatalf("Run() = %d: %s", code, errOut.String())
	}
	if reads != 1 {
		t.Fatalf("master password reads = %d, want 1", reads)
	}
	if !strings.Contains(out.String(), "Vault unlocked for this session.") || !strings.Contains(out.String(), "Session locked.") {
		t.Fatalf("missing shell lifecycle feedback: %q", out.String())
	}
	if _, err := app.OpenSession(path, password); err != nil {
		t.Fatalf("vault remained locked after shell exit: %v", err)
	}
}

func TestShellStoresAndListsWithoutLeakingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	const sentinel = "shell-secret-sentinel"
	if err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	prompts := [][]byte{append([]byte(nil), password...), []byte(sentinel)}
	var out, errOut bytes.Buffer
	shell := Shell{
		Input:  strings.NewReader("set openai.demo\nlist\nlock\n"),
		Stdout: &out,
		Stderr: &errOut,
		ReadSecret: func(string) ([]byte, error) {
			value := prompts[0]
			prompts = prompts[1:]
			return value, nil
		},
		OpenSession: func(got []byte) (*app.Session, error) { return app.OpenSession(path, got) },
	}

	if code := shell.Run(); code != 0 {
		t.Fatalf("Run() = %d: %s", code, errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), sentinel) {
		t.Fatal("secret leaked through shell output")
	}
	if !strings.Contains(out.String(), "openai.demo") {
		t.Fatalf("stored reference missing from output: %q", out.String())
	}
}

func TestShellClosesSessionOnEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	if err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	shell := Shell{
		Input:       strings.NewReader("list\n"),
		Stdout:      &out,
		Stderr:      &errOut,
		ReadSecret:  func(string) ([]byte, error) { return append([]byte(nil), password...), nil },
		OpenSession: func(got []byte) (*app.Session, error) { return app.OpenSession(path, got) },
	}

	if code := shell.Run(); code != 0 {
		t.Fatalf("Run() = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Session locked.") {
		t.Fatalf("EOF did not lock the session: %q", out.String())
	}
	opened, err := app.OpenSession(path, password)
	if err != nil {
		t.Fatalf("vault remained locked after EOF: %v", err)
	}
	opened.Close()
}

func TestParseShellLineRejectsUnclosedQuote(t *testing.T) {
	_, err := parseShellLine("set openai.demo 'shell-secret-sentinel")
	if err == nil {
		t.Fatal("unclosed quote was accepted")
	}
	if strings.Contains(err.Error(), "shell-secret-sentinel") {
		t.Fatal("parser reflected the supplied line")
	}
}
