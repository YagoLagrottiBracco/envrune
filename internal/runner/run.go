package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrInvalidCommand = errors.New("invalid child command")
var ErrChildFailed = errors.New("child process failed")

// CommandNotFoundError means the command is neither a path nor on PATH.
type CommandNotFoundError struct{ Name string }

func (e *CommandNotFoundError) Error() string { return "command not found: " + e.Name }

// ExitError reports a child that ran but did not succeed.
type ExitError struct{ Code int }

func (e *ExitError) Error() string {
	if e.Code < 0 {
		return "the process was terminated by a signal"
	}
	return fmt.Sprintf("the process exited with code %d", e.Code)
}

func (e *ExitError) Is(target error) bool { return target == ErrChildFailed }

// StartError means the child could not be started at all.
type StartError struct {
	Name string
	Err  error
}

func (e *StartError) Error() string        { return fmt.Sprintf("could not start %s: %v", e.Name, e.Err) }
func (e *StartError) Unwrap() error        { return e.Err }
func (e *StartError) Is(target error) bool { return target == ErrChildFailed }

// Spec describes one child process.
type Spec struct {
	Command   []string
	Additions []Pair
	Inherited []string
	Dir       string // working directory; empty means the current one
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	// Group starts the child in its own process group so Stop reaches every
	// process it spawns. The terminal's Ctrl+C then no longer reaches it.
	Group bool
}

// Process is a running child.
type Process struct {
	cmd   *exec.Cmd
	group bool
}

// Start resolves the command through PATH (or relative to Dir when it
// contains a path separator) and starts it.
func Start(spec Spec) (*Process, error) {
	if len(spec.Command) == 0 || spec.Command[0] == "" {
		return nil, ErrInvalidCommand
	}
	name := spec.Command[0]
	lookup := name
	if spec.Dir != "" && strings.ContainsAny(name, `/\`) && !filepath.IsAbs(name) {
		lookup = filepath.Join(spec.Dir, name)
	}
	path, err := exec.LookPath(lookup)
	if err != nil {
		return nil, &CommandNotFoundError{Name: name}
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	cmd, err := childCommand(path, spec.Command)
	if err != nil {
		return nil, &StartError{Name: name, Err: err}
	}
	cmd.Dir = spec.Dir
	cmd.Env = extendEnvironment(spec.Inherited, spec.Additions)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Stdin, spec.Stdout, spec.Stderr
	if spec.Group {
		ownGroup(cmd)
	}
	if err := cmd.Start(); err != nil {
		return nil, &StartError{Name: name, Err: err}
	}
	return &Process{cmd: cmd, group: spec.Group}, nil
}

// Wait returns the child's exit code and an error that explains a failure.
func (p *Process) Wait() (int, error) {
	err := p.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), &ExitError{Code: exit.ExitCode()}
	}
	return 1, &StartError{Name: p.cmd.Args[0], Err: err}
}

// Stop asks the child, and its process group when it has one, to exit.
func (p *Process) Stop() {
	if p.cmd.Process != nil {
		stopTree(p.cmd.Process, p.group)
	}
}

// Run starts the command attached to the terminal and waits for it.
func Run(command []string, additions []Pair, inherited []string, stdout, stderr io.Writer) (int, error) {
	p, err := Start(Spec{Command: command, Additions: additions, Inherited: inherited, Stdin: os.Stdin, Stdout: stdout, Stderr: stderr})
	var missing *CommandNotFoundError
	switch {
	case errors.As(err, &missing):
		return 127, err
	case errors.Is(err, ErrInvalidCommand):
		return 2, err
	case err != nil:
		return 1, err
	}
	return p.Wait()
}

func extendEnvironment(inherited []string, additions []Pair) []string {
	values := make(map[string]string, len(inherited)+len(additions))
	for _, entry := range inherited {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}
	for _, addition := range additions {
		values[addition.Name] = string(addition.Value)
	}
	result := make([]string, 0, len(values))
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}
