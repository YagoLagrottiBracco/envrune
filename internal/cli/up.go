package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/redact"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

var serviceColors = []string{"\x1b[36m", "\x1b[35m", "\x1b[33m", "\x1b[32m", "\x1b[34m", "\x1b[91m"}

// prefixWriter writes each complete line with a "name |" prefix. Writers of
// one `up` share a mutex so lines from different services never interleave.
type prefixWriter struct {
	mu     *sync.Mutex
	out    io.Writer
	prefix string
	buffer []byte
}

func (p *prefixWriter) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buffer = append(p.buffer, data...)
	for {
		i := bytes.IndexByte(p.buffer, '\n')
		if i < 0 {
			break
		}
		if _, err := fmt.Fprintf(p.out, "%s%s\n", p.prefix, bytes.TrimRight(p.buffer[:i], "\r")); err != nil {
			return 0, err
		}
		p.buffer = p.buffer[i+1:]
	}
	return len(data), nil
}

func (p *prefixWriter) flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buffer) > 0 {
		_, _ = fmt.Fprintf(p.out, "%s%s\n", p.prefix, p.buffer)
		p.buffer = nil
	}
}

type service struct {
	name    string
	process *runner.Process
	stdout  *prefixWriter
	stderr  *prefixWriter
	masks   []*redact.Writer // in front of stdout and stderr, when masking
}

// up starts several commands from envrune.yml at once, with one unlock.
// When one exits, the others are stopped, as foreman and Procfile runners do.
func (w Workspace) up(argv []string) int {
	a, err := parseArgs(argv, []string{"env"}, []string{"no-redact"}, false)
	if err != nil {
		return w.usageError("up [command...] [--env <environment>] [--no-redact]")
	}
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	config, err := project.Load(projectPath)
	if err != nil {
		return w.fail(err, "The project configuration is invalid.")
	}
	names := a.positional
	if len(names) == 0 {
		names = config.Up
	}
	if len(names) == 0 {
		for name := range config.Commands {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	status := w.status()
	if len(names) == 0 {
		status.Error("envrune.yml has no commands. Add them under commands:, such as `api: npm run dev`.")
		return 1
	}
	width := 0
	for _, name := range names {
		if _, ok := config.Commands[name]; !ok {
			status.Error(fmt.Sprintf("envrune.yml has no command named %s.", name))
			return 2
		}
		width = max(width, len(name))
	}
	color := status.stdoutColor
	resolved := map[string]app.Resolved{}
	defer func() {
		for _, r := range resolved {
			wipePairs(r.Pairs)
		}
	}()
	type plan struct {
		name, dir string
		command   project.Command
		words     []string
		resolved  app.Resolved
	}
	var plans []plan
	for _, name := range names {
		command := config.Commands[name]
		environment := command.Env
		if a.options["env"] != "" {
			environment = a.options["env"]
		}
		secrets, dir := command.Target(projectPath)
		key := secrets + "\x00" + environment
		r, ok := resolved[key]
		if !ok {
			if r, err = w.resolveCommand(name, command, secrets, environment); err != nil {
				return 1
			}
			resolved[key] = r
		}
		words, err := parseShellLine(command.Run)
		if err != nil || len(words) == 0 {
			status.Error(fmt.Sprintf("commands.%s in envrune.yml has unbalanced quotes.", name))
			return 2
		}
		plans = append(plans, plan{name, dir, command, words, r})
		if !w.maySkipMasking(r, a.flags["no-redact"]) {
			return 1
		}
	}

	// One matcher with every service's values, so a service that prints
	// another one's secret is masked too.
	var all []runner.Pair
	for _, r := range resolved {
		all = append(all, r.Pairs...)
	}
	var matcher *redact.Matcher
	if !a.flags["no-redact"] {
		matcher = pairMatcher(all)
		defer matcher.Wipe()
	}
	var mu sync.Mutex
	var services []*service
	stopAll := func() {
		for _, s := range services {
			s.process.Stop()
		}
	}
	for i, p := range plans {
		prefix := fmt.Sprintf("%-*s | ", width, p.name)
		if color {
			prefix = serviceColors[i%len(serviceColors)] + prefix + ansiReset
		}
		s := &service{name: p.name, stdout: &prefixWriter{mu: &mu, out: w.Stdout, prefix: prefix}, stderr: &prefixWriter{mu: &mu, out: w.Stderr, prefix: prefix}}
		spec := runner.Spec{Command: p.words, Additions: p.resolved.Pairs, Inherited: w.environ(), Dir: p.dir, Stdout: s.stdout, Stderr: s.stderr, Group: true}
		if matcher != nil && !matcher.Empty() {
			s.masks = []*redact.Writer{redact.NewWriter(s.stdout, matcher), redact.NewWriter(s.stderr, matcher)}
			spec.Stdout, spec.Stderr = s.masks[0], s.masks[1]
		}
		s.process, err = runner.Start(spec)
		if err != nil {
			stopAll()
			return w.fail(err, fmt.Sprintf("%s could not start.", p.name))
		}
		services = append(services, s)
		status.Info(fmt.Sprintf("Started %s (%s) with %d variables from %s.", p.name, strings.Join(p.words, " "), len(p.resolved.Pairs), sourceLabel(p.command, p.resolved.Environment)))
	}
	status.Info("Press Ctrl+C to stop every service.")

	type exit struct {
		name string
		code int
		err  error
	}
	exits := make(chan exit, len(services))
	for _, s := range services {
		go func(s *service) {
			code, err := s.process.Wait()
			for _, mask := range s.masks {
				_ = mask.Close()
			}
			s.stdout.flush()
			s.stderr.flush()
			exits <- exit{s.name, code, err}
		}(s)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	result, stopping := 0, false
	for remaining := len(services); remaining > 0; {
		select {
		case <-signals:
			if !stopping {
				status.Info("Stopping every service...")
				stopping = true
				stopAll()
			}
		case e := <-exits:
			remaining--
			if e.err != nil && !stopping {
				status.Error(fmt.Sprintf("%s: %s", e.name, describe(e.err, "exited")))
				if result == 0 {
					result = e.code
				}
			} else if !stopping {
				status.Info(fmt.Sprintf("%s exited.", e.name))
			}
			if !stopping && remaining > 0 {
				status.Info("Stopping the other services...")
				stopping = true
				stopAll()
			}
		}
	}
	// Every service has exited; this ends what they left behind, such as a
	// server started by a script that already returned.
	stopAll()
	return result
}
