package cli

import (
	"bytes"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

func TestShellReadsMasterPasswordOnceAndClosesSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	if _, err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
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
	feedback := out.String() + errOut.String()
	if !strings.Contains(feedback, "Vault unlocked for this session.") || !strings.Contains(feedback, "Session locked.") {
		t.Fatalf("missing shell lifecycle feedback: %q", feedback)
	}
	if _, err := app.OpenSession(path, password); err != nil {
		t.Fatalf("vault remained locked after shell exit: %v", err)
	}
}

func TestShellStoresAndListsWithoutLeakingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	const sentinel = "shell-secret-sentinel"
	if _, err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	prompts := [][]byte{append([]byte(nil), password...), []byte(sentinel), []byte(sentinel)}
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
	if _, err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
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
	if !strings.Contains(out.String()+errOut.String(), "Session locked.") {
		t.Fatalf("EOF did not lock the session: %q", out.String()+errOut.String())
	}
	opened, err := app.OpenSession(path, password)
	if err != nil {
		t.Fatalf("vault remained locked after EOF: %v", err)
	}
	opened.Close()
}

func TestShellUIUsesExistingSessionWithoutSecondPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	if _, err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	reads, starts := 0, 0
	var out, errOut bytes.Buffer
	shell := Shell{
		Input:  strings.NewReader("ui --no-browser\nexit\n"),
		Stdout: &out,
		Stderr: &errOut,
		ReadSecret: func(string) ([]byte, error) {
			reads++
			return append([]byte(nil), password...), nil
		},
		OpenSession: func(got []byte) (*app.Session, error) { return app.OpenSession(path, got) },
		StartUI: func(session *app.Session, args []string, stdout, stderr io.Writer) int {
			starts++
			if session == nil || !reflect.DeepEqual(args, []string{"--no-browser"}) {
				t.Fatal("shell did not pass the active session to the UI")
			}
			return 0
		},
	}

	if code := shell.Run(); code != 0 {
		t.Fatalf("Run() = %d: %s", code, errOut.String())
	}
	if reads != 1 || starts != 1 {
		t.Fatalf("password reads=%d UI starts=%d", reads, starts)
	}
}

func TestShellClosesSessionOnInterrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	if _, err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	interrupt := make(chan struct{})
	close(interrupt)
	var out, errOut bytes.Buffer
	shell := Shell{
		Input:     strings.NewReader(""),
		Stdout:    &out,
		Stderr:    &errOut,
		Interrupt: interrupt,
		ReadSecret: func(string) ([]byte, error) {
			return append([]byte(nil), password...), nil
		},
		OpenSession: func(got []byte) (*app.Session, error) { return app.OpenSession(path, got) },
	}

	if code := shell.Run(); code != 130 {
		t.Fatalf("Run() = %d, want 130: %s", code, errOut.String())
	}
	if !strings.Contains(out.String()+errOut.String(), "Session locked.") {
		t.Fatalf("interrupt did not lock the session: %q", out.String()+errOut.String())
	}
	opened, err := app.OpenSession(path, password)
	if err != nil {
		t.Fatalf("vault remained locked after interrupt: %v", err)
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

func TestShellsShareVaultAndExplainFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	if _, err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	other, err := app.OpenSession(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Set("demo.api-key", []byte("value")); err != nil {
		t.Fatal(err)
	}
	projectDir := t.TempDir()
	projectPath := filepath.Join(projectDir, "envrune.yml")
	if err := project.WriteAtomic(projectPath, project.Config{Version: 1, Project: "demo", Environments: map[string]map[string]domain.Reference{
		"development": {"API_KEY": "demo.api-key", "DATABASE_URL": "demo.database-url.development"},
	}}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	shell := Shell{
		Input:       strings.NewReader("list\nrun --env production -- anything\nrun --env development -- anything\nexit\n"),
		Stdout:      &out,
		Stderr:      &errOut,
		ReadSecret:  func(string) ([]byte, error) { return append([]byte(nil), password...), nil },
		OpenSession: func(got []byte) (*app.Session, error) { return app.OpenSession(path, got) },
		FindProject: func(string) (string, error) { return projectPath, nil },
	}
	if code := shell.Run(); code != 0 {
		t.Fatalf("Run() = %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "demo.api-key") {
		t.Fatalf("shell did not see a secret stored by another session: %q", out.String())
	}
	for _, want := range []string{
		`Environment "production" does not exist; available: development.`,
		"demo.database-url.development (used by DATABASE_URL)",
	} {
		if !strings.Contains(errOut.String(), want) {
			t.Fatalf("missing %q in %q", want, errOut.String())
		}
	}
}

func TestShellRunReportsMissingCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("shell-master-password")
	if _, err := (app.VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	projectPath := filepath.Join(t.TempDir(), "envrune.yml")
	if err := project.WriteAtomic(projectPath, project.Config{Version: 1, Project: "demo", Environments: map[string]map[string]domain.Reference{"development": {}}}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	shell := Shell{
		Input:       strings.NewReader("run --env development -- envrune-no-such-command\nexit\n"),
		Stdout:      &out,
		Stderr:      &errOut,
		ReadSecret:  func(string) ([]byte, error) { return append([]byte(nil), password...), nil },
		OpenSession: func(got []byte) (*app.Session, error) { return app.OpenSession(path, got) },
		FindProject: func(string) (string, error) { return projectPath, nil },
	}
	_ = shell.Run()
	if !strings.Contains(errOut.String(), "Command not found: envrune-no-such-command") {
		t.Fatalf("missing command was not reported: %q", errOut.String())
	}
}
