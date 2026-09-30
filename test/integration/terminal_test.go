//go:build integration

package integration

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

// screen collects what a pseudo-terminal shows.
type screen struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// waitFor waits until the screen shows text after position from, and
// returns the position after it.
func (s *screen) waitFor(t *testing.T, from int, text string) int {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if all := s.String(); len(all) >= from {
			if i := strings.Index(all[from:], text); i >= 0 {
				return from + i + len(text)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the terminal never showed %q:\n%s", text, s.String())
	return 0
}

// TestShellRunsChildrenInATerminal runs `envrune shell` in a pseudo-terminal,
// as a user's terminal would, and types into it. `run` inside the shell must
// give the child a terminal of its own, forward typed input to it, mask the
// value it prints, and hand the keyboard back to the shell afterwards.
func TestShellRunsChildrenInATerminal(t *testing.T) {
	h := newHarness(t)
	h.set("demo.api-key", "sk-live-terminal-value")
	dir := h.project("app", devConfig)
	keys, typing := io.Pipe()
	defer typing.Close()
	var out screen
	shell, err := runner.Start(runner.Spec{
		Command:   []string{envruneBin, "shell"},
		Inherited: h.environ(),
		Dir:       dir,
		Stdin:     keys,
		Stdout:    &out,
		Terminal:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Stop()
	typeLine := func(line string) {
		if _, err := io.WriteString(typing, line+"\r"); err != nil {
			t.Fatal(err)
		}
	}
	at := out.waitFor(t, 0, "envrune [unlocked] >")
	typeLine("run -- probe tty print API_KEY read")
	at = out.waitFor(t, at, "API_KEY=")
	typeLine("typed-in-the-child")
	at = out.waitFor(t, at, "got typed-in-the-child")
	at = out.waitFor(t, at, "envrune [unlocked] >")
	typeLine("list")
	at = out.waitFor(t, at, "1 secret reference")
	typeLine("exit")
	if code, err := shell.Wait(); code != 0 {
		t.Fatalf("shell exited with %d, %v:\n%s", code, err, out.String())
	}
	screen := out.String()
	expect(t, screen, "tty=true", "API_KEY=****")
	if strings.Contains(screen, "terminal-value") {
		t.Fatalf("the terminal showed the value:\n%s", screen)
	}
}
