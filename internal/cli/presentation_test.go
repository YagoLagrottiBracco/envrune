package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestPresenterWritesPlainTextWhenOutputIsNotATerminal(t *testing.T) {
	var out, errOut bytes.Buffer
	presenter := NewPresenter(&out, &errOut, func(string) string { return "" })

	presenter.Success("Vault initialized.")
	presenter.Error("Vault is unavailable.")

	if got := out.String(); got != "" {
		t.Fatalf("stdout = %q", got)
	}
	if got := errOut.String(); got != "[OK] Vault initialized.\n[ERROR] Vault is unavailable.\n" {
		t.Fatalf("stderr = %q", got)
	}
	if strings.Contains(out.String()+errOut.String(), "\x1b[") {
		t.Fatal("redirected output contained ANSI styling")
	}
}

func TestPresenterHonorsNoColor(t *testing.T) {
	old := terminalWriter
	terminalWriter = func(any) bool { return true }
	t.Cleanup(func() { terminalWriter = old })
	var out, errOut bytes.Buffer

	presenter := NewPresenter(&out, &errOut, func(key string) string {
		if key == "NO_COLOR" {
			return "1"
		}
		return "xterm-256color"
	})
	presenter.Warn("Plaintext export requires confirmation.")

	if got := out.String(); got != "" {
		t.Fatalf("stdout = %q", got)
	}
	if got := errOut.String(); got != "[WARNING] Plaintext export requires confirmation.\n" {
		t.Fatalf("stderr = %q", got)
	}
	if strings.Contains(errOut.String(), "\x1b[") {
		t.Fatal("NO_COLOR output contained ANSI styling")
	}
}

func TestPresenterStylesTerminalOutput(t *testing.T) {
	old := terminalWriter
	terminalWriter = func(any) bool { return true }
	t.Cleanup(func() { terminalWriter = old })
	var out, errOut bytes.Buffer

	presenter := NewPresenter(&out, &errOut, func(key string) string {
		if key == "TERM" {
			return "xterm-256color"
		}
		return ""
	})
	presenter.Info("Vault unlocked for this session.")

	if got := errOut.String(); got != "\x1b[34m[INFO]\x1b[0m Vault unlocked for this session.\n" {
		t.Fatalf("stderr = %q", got)
	}
}
