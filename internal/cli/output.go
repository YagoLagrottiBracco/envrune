package cli

import (
	"io"
	"os"

	"github.com/YagoLagrottiBracco/envrune/internal/redact"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"golang.org/x/term"
)

// childOutput is where a child's output goes: through masking writers
// unless masking is off, and through a pseudo-terminal when Envrune itself
// runs in a terminal, so the child still behaves as in one.
type childOutput struct {
	Stdout, Stderr io.Writer
	Terminal       bool
	matcher        *redact.Matcher
	writers        []*redact.Writer
}

// childOutput masks the values in pairs. With mask false, or when no value
// is long enough to be masked, the child writes straight to Envrune's own
// output, as in EnvRune 0.1.0.
func (w Workspace) childOutput(pairs []runner.Pair, mask bool) *childOutput {
	out := &childOutput{Stdout: w.Stdout, Stderr: w.Stderr}
	if !mask {
		return out
	}
	out.matcher = pairMatcher(pairs)
	if out.matcher.Empty() {
		return out
	}
	stdout, stderr := redact.NewWriter(w.Stdout, out.matcher), redact.NewWriter(w.Stderr, out.matcher)
	out.Stdout, out.Stderr, out.writers = stdout, stderr, []*redact.Writer{stdout, stderr}
	out.Terminal = w.Stdout == io.Writer(os.Stdout) && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	return out
}

// pairMatcher looks for the values of pairs, reported by variable name.
func pairMatcher(pairs []runner.Pair) *redact.Matcher {
	secrets := make([]redact.Secret, len(pairs))
	for i, pair := range pairs {
		secrets[i] = redact.Secret{Name: pair.Name, Value: pair.Value}
	}
	return redact.NewMatcher(secrets)
}

// Close writes what the masking writers kept back and wipes the values.
func (o *childOutput) Close() {
	for _, writer := range o.writers {
		_ = writer.Close()
	}
	if o.matcher != nil {
		o.matcher.Wipe()
	}
}
