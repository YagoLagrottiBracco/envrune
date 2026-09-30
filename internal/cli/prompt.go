package cli

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

var ErrSecureInputRequired = errors.New("secure interactive input is required")

type SecretPrompt struct {
	IsTerminal   func(int) bool
	ReadPassword func(int) ([]byte, error)
	Output       io.Writer
}

func (p SecretPrompt) Read(label string) ([]byte, error) {
	isTerminal := p.IsTerminal
	if isTerminal == nil {
		isTerminal = term.IsTerminal
	}
	if !isTerminal(int(os.Stdin.Fd())) {
		return nil, ErrSecureInputRequired
	}
	read := p.ReadPassword
	if read == nil {
		read = term.ReadPassword
	}
	out := p.Output
	if out == nil {
		out = os.Stderr
	}
	_, _ = io.WriteString(out, label+": ")
	v, err := read(int(os.Stdin.Fd()))
	_, _ = io.WriteString(out, "\n")
	if err != nil {
		return nil, ErrSecureInputRequired
	}
	return []byte(strings.TrimSuffix(string(v), "\n")), nil
}
