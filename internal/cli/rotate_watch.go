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

// rotationWatch lets a running command notice that a value it was started
// with has been replaced: in the vault, in the team file, or in the cloud,
// where it first asks the server whether anything moved. See
// docs/managed-keys.md.
type rotationWatch struct {
	secrets     string // the envrune.yml that supplies the values
	environment string
	restart     bool // stop the command and start it again with the new values
	// extra are variables the command gets that are not resolved from
	// envrune.yml, such as the proxy's for sensitive secrets; they stay the
	// same across restarts.
	extra []runner.Pair
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
	// Copies: the caller wipes what this returns.
	for _, p := range watch.extra {
		resolved.Pairs = append(resolved.Pairs, runner.Pair{Name: p.Name, Value: append([]byte(nil), p.Value...)})
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

// runWatching runs spec like runChild and, while it runs, looks for replaced
// values. Without watch.restart it says once that the command must be
// restarted to use them. With it, it stops the command and starts it again
// with the new values, for as long as the command keeps running.
func (w Workspace) runWatching(spec runner.Spec, mask bool, watch *rotationWatch) int {
	if watch == nil || w.Session == nil {
		return w.runChild(spec, mask)
	}
	// The watcher writes status lines while the command writes its output.
	// Files take concurrent writes; anything else gets one writer at a time.
	var mu sync.Mutex
	w.Stdout, w.Stderr = serialized(w.Stdout, &mu), serialized(w.Stderr, &mu)
	if !watch.restart {
		done := make(chan struct{})
		// Nothing is said once the command has ended, even by a check that
		// was under way.
		var say sync.Mutex
		ended := false
		defer func() {
			close(done)
			say.Lock()
			ended = true
			say.Unlock()
		}()
		// Its own copy of the values: the caller wipes spec's when the
		// command ends, which may be while this is still comparing.
		started := make([]runner.Pair, len(spec.Additions))
		for i, p := range spec.Additions {
			started[i] = runner.Pair{Name: p.Name, Value: append([]byte(nil), p.Value...)}
		}
		go func() {
			defer wipePairs(started)
			ticker := time.NewTicker(rotationPollInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if fresh, names := w.changed(watch, started); len(names) > 0 {
						wipePairs(fresh)
						say.Lock()
						if !ended {
							w.status().Warn(fmt.Sprintf("New values arrived for %s. Restart this command to use them, or start it with --restart-on-rotate.", strings.Join(names, ", ")))
						}
						say.Unlock()
						return
					}
				}
			}
		}()
		return w.runChild(spec, mask)
	}

	// Restarting needs to stop everything the command started, so it runs in
	// its own process group, and this process passes Ctrl+C on to it.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	ticker := time.NewTicker(rotationPollInterval)
	defer ticker.Stop()
	pairs := spec.Additions
	var owned []runner.Pair // pairs from a later resolve, wiped here
	defer func() { wipePairs(owned) }()
	for {
		output := w.childOutput(pairs, mask)
		run := spec
		run.Additions, run.Group = pairs, true
		run.Stdin, run.Stdout, run.Stderr = os.Stdin, output.Stdout, output.Stderr
		process, err := runner.Start(run)
		if err != nil {
			output.Close()
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
		for fresh == nil {
			select {
			case e := <-exited:
				process.Stop() // what it left behind
				output.Close()
				if e.err != nil {
					w.status().Error(describe(e.err, "The command failed."))
				}
				return e.code
			case <-signals:
				process.Stop()
				e := <-exited
				output.Close()
				return e.code
			case <-ticker.C:
				var names []string
				fresh, names = w.changed(watch, pairs)
				if len(names) > 0 {
					w.status().Info(fmt.Sprintf("New values arrived for %s: restarting %s.", strings.Join(names, ", "), spec.Command[0]))
				}
			}
		}
		process.Stop()
		<-exited
		output.Close()
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
