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
}

// up starts several commands from envrune.yml at once, with one unlock.
// When one exits, the others are stopped, as foreman and Procfile runners do.
func (w Workspace) up(argv []string) int {
	a, err := parseArgs(argv, []string{"env"}, nil, false)
	if err != nil {
		return w.usageError("up [command...] [--env <environment>]")
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
	var mu sync.Mutex
	var services []*service
	stopAll := func() {
		for _, s := range services {
			s.process.Stop()
		}
	}
	for i, name := range names {
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
				stopAll()
				return 1
			}
			resolved[key] = r
		}
		words, err := parseShellLine(command.Run)
		if err != nil || len(words) == 0 {
			stopAll()
			status.Error(fmt.Sprintf("commands.%s in envrune.yml has unbalanced quotes.", name))
			return 2
		}
		prefix := fmt.Sprintf("%-*s | ", width, name)
		if color {
			prefix = serviceColors[i%len(serviceColors)] + prefix + ansiReset
		}
		s := &service{name: name, stdout: &prefixWriter{mu: &mu, out: w.Stdout, prefix: prefix}, stderr: &prefixWriter{mu: &mu, out: w.Stderr, prefix: prefix}}
		s.process, err = runner.Start(runner.Spec{
			Command:   words,
			Additions: r.Pairs,
			Inherited: w.environ(),
			Dir:       dir,
			Stdout:    s.stdout,
			Stderr:    s.stderr,
			Group:     true,
		})
		if err != nil {
			stopAll()
			return w.fail(err, fmt.Sprintf("%s could not start.", name))
		}
		services = append(services, s)
		status.Info(fmt.Sprintf("Started %s (%s) with %d variables from %s.", name, strings.Join(words, " "), len(r.Pairs), sourceLabel(command, r.Environment)))
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
