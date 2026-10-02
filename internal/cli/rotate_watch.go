package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

// rotationPollInterval is how often a running command looks for replaced
// values. Tests shorten it.
var rotationPollInterval = 30 * time.Second

// rotationWatch is what `run` and named commands know about the command
// they start, beyond its values: where the values come from, so they can be
// resolved again when one is replaced (docs/managed-keys.md), and what the
// command gets besides them.
type rotationWatch struct {
	secrets     string // the envrune.yml that supplies the values
	environment string
	restart     bool // stop the command and start it again with the new values
	// extra are variables that are not resolved from envrune.yml, such as
	// the proxy's for sensitive secrets; they stay the same across restarts.
	extra []runner.Pair
	// templates are files to fill in for this run only, as variable → path.
	templates map[string]string
}

// changed resolves the command's values again and names the variables whose
// value differs from pairs, which are not modified. The caller wipes fresh.
func (w Workspace) changed(watch *rotationWatch, pairs []runner.Pair) (fresh []runner.Pair, names []string) {
	w.freshen(watch.secrets, watch.environment)
	resolved, err := w.Session.Resolve(watch.secrets, watch.environment)
	if err != nil {
		// Locked, offline past the limit, or a value removed meanwhile: the
		// command keeps what it has.
		wipePairs(resolved.Pairs)
		return nil, nil
	}
	current := map[string][]byte{}
	for _, p := range pairs {
		current[p.Name] = p.Value
	}
	for _, p := range resolved.Pairs {
		if old, ok := current[p.Name]; !ok || !bytes.Equal(old, p.Value) {
			names = append(names, p.Name)
		}
	}
	if len(resolved.Pairs) != len(pairs) && len(names) == 0 {
		names = append(names, "the set of variables")
	}
	sort.Strings(names)
	if len(names) == 0 {
		wipePairs(resolved.Pairs)
		return nil, nil
	}
	return resolved.Pairs, names
}

// runWatching runs spec, whose Additions are the values resolved from
// envrune.yml. Before it starts the command it writes the files the project
// asks for (stage) and adds watch.extra. While the command runs it looks for
// replaced values: without watch.restart it says once that the command must
// be restarted to use them; with it, it stops the command and starts it
// again with the new values. It removes the files when the command ends,
// also when it is interrupted.
func (w Workspace) runWatching(spec runner.Spec, mask bool, watch *rotationWatch) int {
	if watch == nil || w.Session == nil {
		return w.runChild(spec, mask)
	}
	// The watcher writes status lines while the command writes its output.
	// Files take concurrent writes; anything else gets one writer at a time.
	var mu sync.Mutex
	w.Stdout, w.Stderr = serialized(w.Stdout, &mu), serialized(w.Stderr, &mu)

	// This process outlives an interrupt, to remove what it wrote. Without
	// a group of its own the command receives the terminal's Ctrl+C itself;
	// with one, and for a request to terminate, it is passed on.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	ticker := time.NewTicker(rotationPollInterval)
	defer ticker.Stop()

	pairs := spec.Additions
	var owned []runner.Pair // pairs from a later resolve, wiped here
	defer func() { wipePairs(owned) }()
	warned := false
	for {
		staged, cleanup, err := w.stage(watch.secrets, pairs, watch.templates)
		if err != nil {
			// It names files and variables, never a value.
			w.status().Error(sentence(strings.TrimRight(err.Error(), ".")))
			return 1
		}
		given := append(staged, watch.extra...)
		output := w.childOutput(given, mask)
		run := spec
		run.Additions, run.Group = given, watch.restart
		run.Stdin, run.Stdout, run.Stderr = os.Stdin, output.Stdout, output.Stderr
		if !watch.restart {
			run.Terminal = output.Terminal
		}
		process, err := runner.Start(run)
		if err != nil {
			output.Close()
			cleanup()
			var missing *runner.CommandNotFoundError
			code := 1
			switch {
			case errors.As(err, &missing):
				code = 127
			case errors.Is(err, runner.ErrInvalidCommand):
				code = 2
			}
			w.status().Error(describe(err, "The command could not be run."))
			return code
		}
		type exit struct {
			code int
			err  error
		}
		exited := make(chan exit, 1)
		go func() {
			code, err := process.Wait()
			exited <- exit{code, err}
		}()
		var fresh []runner.Pair
		stopping := false
		for fresh == nil {
			select {
			case e := <-exited:
				if watch.restart {
					process.Stop() // what it left behind
				}
				output.Close()
				cleanup()
				if e.err != nil && !stopping {
					w.status().Error(describe(e.err, "The command failed."))
				}
				return e.code
			case sig := <-signals:
				if watch.restart || sig == syscall.SIGTERM {
					stopping = true
					process.Stop()
				}
			case <-ticker.C:
				if stopping || warned {
					continue
				}
				next, names := w.changed(watch, pairs)
				if len(names) == 0 {
					continue
				}
				if watch.restart {
					w.status().Info(fmt.Sprintf("New values arrived for %s: restarting %s.", strings.Join(names, ", "), spec.Command[0]))
					fresh = next
					continue
				}
				wipePairs(next)
				warned = true
				w.status().Warn(fmt.Sprintf("New values arrived for %s. Restart this command to use them, or start it with --restart-on-rotate.", strings.Join(names, ", ")))
			}
		}
		process.Stop()
		<-exited
		output.Close()
		cleanup()
		wipePairs(owned)
		pairs, owned = fresh, fresh
	}
}

// lockedWriter lets several goroutines write to a writer that is not safe
// for that, one at a time.
type lockedWriter struct {
	mu  *sync.Mutex
	out io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.out.Write(p)
}

// serialized returns out itself when it is a file, which the terminal
// checks rely on, and a locked writer in front of anything else.
func serialized(out io.Writer, mu *sync.Mutex) io.Writer {
	if _, ok := out.(*os.File); ok || out == nil {
		return out
	}
	return &lockedWriter{mu: mu, out: out}
}
