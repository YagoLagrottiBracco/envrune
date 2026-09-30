package cli

import (
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

var ErrSecureInputRequired = errors.New("secure interactive input is required")

// ErrMultilineInput means more input was waiting after the secret line, as
// happens when a multi-line block is pasted. The whole input is discarded.
var ErrMultilineInput = errors.New("multi-line input was discarded")
var ErrValueConfirmation = errors.New("value confirmation does not match")
var ErrEmptyValue = errors.New("value is empty")

type SecretPrompt struct {
	IsTerminal     func(int) bool
	ReadPassword   func(int) ([]byte, error)
	DiscardPending func(int) bool
	Output         io.Writer
}

func (p SecretPrompt) Read(label string) ([]byte, error) {
	isTerminal := p.IsTerminal
	if isTerminal == nil {
		isTerminal = term.IsTerminal
	}
	fd := int(os.Stdin.Fd())
	if !isTerminal(fd) {
		return nil, ErrSecureInputRequired
	}
	read := p.ReadPassword
	if read == nil {
		read = term.ReadPassword
	}
	discard := p.DiscardPending
	if discard == nil {
		discard = discardPendingInput
	}
	out := p.Output
	if out == nil {
		out = os.Stderr
	}
	_, _ = io.WriteString(out, label+": ")
	v, err := read(fd)
	_, _ = io.WriteString(out, "\n")
	if err != nil {
		return nil, ErrSecureInputRequired
	}
	if discard(fd) {
		wipe(v)
		return nil, ErrMultilineInput
	}
	return []byte(strings.TrimSuffix(string(v), "\n")), nil
}

// readConfirmedValue asks for a secret value twice, like the master password,
// so a paste that was cut short or split across lines is never stored.
func readConfirmedValue(read func(string) ([]byte, error), label string) ([]byte, error) {
	value, err := read(label)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, ErrEmptyValue
	}
	confirmation, err := read("Confirm " + strings.ToLower(label[:1]) + label[1:])
	if err != nil {
		wipe(value)
		return nil, err
	}
	defer wipe(confirmation)
	if subtle.ConstantTimeCompare(value, confirmation) != 1 {
		wipe(value)
		return nil, ErrValueConfirmation
	}
	return value, nil
}
