package cli

import (
	"errors"
	"io"
	"testing"
)

func TestSecretPromptRejectsNonTerminalInput(t *testing.T) {
	prompt := SecretPrompt{IsTerminal: func(int) bool { return false }}
	if _, err := prompt.Read("Master password"); err == nil {
		t.Fatal("expected terminal-only error")
	}
}

func TestSecretPromptDiscardsMultilinePaste(t *testing.T) {
	prompt := SecretPrompt{
		IsTerminal:     func(int) bool { return true },
		ReadPassword:   func(int) ([]byte, error) { return []byte("first-line"), nil },
		DiscardPending: func(int) bool { return true },
		Output:         io.Discard,
	}
	if _, err := prompt.Read("Secret value"); !errors.Is(err, ErrMultilineInput) {
		t.Fatalf("Read() error = %v, want ErrMultilineInput", err)
	}
}

func TestConfirmedValueRejectsMismatchAndEmpty(t *testing.T) {
	answers := func(values ...string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) {
			value := values[0]
			values = values[1:]
			return []byte(value), nil
		}
	}
	if _, err := readConfirmedValue(answers("abc", "abd"), "Secret value"); !errors.Is(err, ErrValueConfirmation) {
		t.Fatalf("mismatch error = %v", err)
	}
	if _, err := readConfirmedValue(answers(""), "Secret value"); !errors.Is(err, ErrEmptyValue) {
		t.Fatalf("empty error = %v", err)
	}
	value, err := readConfirmedValue(answers("abc", "abc"), "Secret value")
	if err != nil || string(value) != "abc" {
		t.Fatalf("readConfirmedValue() = %q, %v", value, err)
	}
}
