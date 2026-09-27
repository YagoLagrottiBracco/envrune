package cli

import "testing"

func TestSecretPromptRejectsNonTerminalInput(t *testing.T) {
	prompt := SecretPrompt{IsTerminal: func(int) bool { return false }}
	if _, err := prompt.Read("Master password"); err == nil {
		t.Fatal("expected terminal-only error")
	}
}
