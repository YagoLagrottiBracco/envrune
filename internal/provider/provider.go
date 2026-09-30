// Package provider moves values between the vault and hosting services or
// secret managers, for `envrune pull` and `envrune push`. Values travel
// only through a service's HTTPS API or through the standard input and
// output of its official CLI, never as command-line arguments, which other
// processes can read, and never through files.
package provider

import (
	"context"
	"errors"
	"os/exec"
	"sort"
)

// Value is one variable read from or written to a service. The caller wipes
// Value.
type Value struct {
	Name  string
	Value []byte
}

// Options are the provider's own flags, such as --repo for GitHub.
type Options map[string]string

// Provider is one service. It implements Puller, Pusher, or both.
type Provider interface {
	// Name is what users type: `envrune pull <name>`.
	Name() string
	// Flags lists the options the provider accepts.
	Flags() []string
	// Target says where values come from or go, for confirmations.
	Target(environment string, opts Options) string
}

// Puller reads values from a service.
type Puller interface {
	Provider
	Pull(ctx context.Context, environment string, opts Options) ([]Value, Notes, error)
}

// Pusher writes values to a service.
type Pusher interface {
	Provider
	Push(ctx context.Context, environment string, values []Value, opts Options) error
}

// Notes are things a pull could not bring, such as write-only values, named
// so the user can act on them.
type Notes []string

// ErrUnsupported means the provider cannot pull or cannot push.
var ErrUnsupported = errors.New("not supported by this provider")

var registry = map[string]Provider{}

// Register adds a provider; the built-in ones register themselves, and
// tests add fakes.
func Register(p Provider) { registry[p.Name()] = p }

func init() {
	Register(GitHub{})
	Register(Vercel{})
	Register(OnePassword{})
}

// Get returns the provider with the given name.
func Get(name string) (Provider, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names lists the providers that can pull (pull true) or push.
func Names(pull bool) []string {
	var out []string
	for name, p := range registry {
		if _, ok := p.(Puller); ok && pull {
			out = append(out, name)
		}
		if _, ok := p.(Pusher); ok && !pull {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// execCommand builds the commands providers run; tests replace it.
var execCommand = exec.CommandContext

// lookPath finds the CLIs providers need; tests replace it.
var lookPath = exec.LookPath

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
