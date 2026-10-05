package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"golang.org/x/term"
)

// Onboarding performs the explicit first-use vault setup flow.
type Onboarding struct {
	VaultPath  string
	Stdout     io.Writer
	Stderr     io.Writer
	ReadChoice func(string) (string, error)
	ReadSecret func(string) ([]byte, error)
}

func executeOnboarding(stdout, stderr io.Writer) int {
	path, err := vaultPath(os.Getenv)
	if err != nil {
		NewPresenter(stdout, stderr, os.Getenv).Error("Vault path is unavailable.")
		return 1
	}
	prompt := ChoicePrompt{Output: stderr}
	return Onboarding{
		VaultPath:  path,
		Stdout:     stdout,
		Stderr:     stderr,
		ReadChoice: prompt.Read,
		ReadSecret: (SecretPrompt{Output: stderr}).Read,
	}.Run()
}

func (o Onboarding) Run() int {
	status := NewPresenter(o.Stdout, o.Stderr, os.Getenv)
	if o.VaultPath == "" || o.Stdout == nil || o.Stderr == nil || o.ReadChoice == nil || o.ReadSecret == nil {
		status.Error("Interactive setup is unavailable.")
		return 1
	}

	info, err := os.Stat(o.VaultPath)
	if err == nil {
		if !info.Mode().IsRegular() {
			status.Error("Vault path is unavailable.")
			return 1
		}
		status.Info("Vault is ready. Run `envrune shell` to begin.")
		return 0
	}
	if !errors.Is(err, fs.ErrNotExist) {
		status.Error("Vault path is unavailable.")
		return 1
	}

	status.Info("Envrune is not initialized yet.")
	choice, err := o.ReadChoice("Create a local encrypted vault now? [y/N]")
	if err != nil {
		status.Error("Interactive setup is required. Run `envrune init` in a terminal.")
		return 1
	}
	if !acceptsSetup(choice) {
		status.Info("Initialization cancelled.")
		return 0
	}

	password, err := o.ReadSecret("Master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	defer wipe(password)
	confirmation, err := o.ReadSecret("Confirm master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	defer wipe(confirmation)
	recovery, err := (app.VaultService{}).Init(o.VaultPath, password, confirmation)
	if err != nil {
		status.Error(describe(err, "Vault initialization failed. Check the passwords and try again."))
		return 1
	}
	defer wipe(recovery)
	status.Success("Vault initialized. Run `envrune shell` to begin.")
	showRecoveryKey(o.Stdout, status, recovery, vaultRecoveryUse, vaultRecoveryAgain)
	return 0
}

func acceptsSetup(choice string) bool {
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// ChoicePrompt reads a visible, non-secret choice from the controlling
// terminal. It intentionally reads one byte at a time so it cannot buffer a
// master password pasted immediately after the choice.
type ChoicePrompt struct {
	IsTerminal func(int) bool
	ReadLine   func() (string, error)
	Output     io.Writer
}

func (p ChoicePrompt) Read(label string) (string, error) {
	isTerminal := p.IsTerminal
	if isTerminal == nil {
		isTerminal = term.IsTerminal
	}
	if !isTerminal(int(os.Stdin.Fd())) {
		return "", ErrSecureInputRequired
	}
	out := p.Output
	if out == nil {
		out = os.Stderr
	}
	_, _ = fmt.Fprint(out, label+" ")
	readLine := p.ReadLine
	if readLine == nil {
		readLine = readChoiceLine
	}
	value, err := readLine()
	if err != nil {
		_, _ = fmt.Fprintln(out)
		return "", ErrSecureInputRequired
	}
	return value, nil
}

func readChoiceLine() (string, error) {
	const maxChoiceBytes = 16
	value := make([]byte, 0, maxChoiceBytes)
	var one [1]byte
	for {
		count, err := os.Stdin.Read(one[:])
		if count > 0 {
			switch one[0] {
			case '\n':
				return string(value), nil
			case '\r':
				continue
			default:
				if len(value) == maxChoiceBytes {
					return "", ErrSecureInputRequired
				}
				value = append(value, one[0])
			}
		}
		if err != nil {
			return "", err
		}
	}
}
