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
	// Terminal attaches the child to a new pseudo-terminal sized like this
	// process's terminal, and sends everything it prints, standard error
	// included, to Stdout, and Stderr is ignored. When Stdin is os.Stdin and
	// a terminal, it is switched to raw mode and forwarded to the child until
	// the child exits, so keys such as Ctrl+C reach the child as they would
	// without Envrune. Any other Stdin is copied to the child's terminal as
	// typed input. Where no pseudo-terminal is available, the child gets
	// pipes instead.
	Terminal bool
}

// Process is a running child.
type Process struct {
	cmd     *exec.Cmd // nil when the child was started through ConPTY
	process *os.Process
	name    string
	group   bool
	tree    tree
	console *console // the pseudo-terminal, when Spec.Terminal was set
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
	env := extendEnvironment(spec.Inherited, spec.Additions)
	if spec.Terminal && terminalAvailable() {
		return startTerminal(name, path, spec, env)
	}
	cmd, err := childCommand(path, spec.Command)
	if err != nil {
		return nil, &StartError{Name: name, Err: err}
	}
	cmd.Dir = spec.Dir
	cmd.Env = env
	stdout, stderr := spec.Stdout, spec.Stderr
	if spec.Terminal {
		stderr = stdout // one stream, as in a terminal
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Stdin, stdout, stderr
	if spec.Group {
		ownGroup(cmd)
	}
	if err := cmd.Start(); err != nil {
		return nil, &StartError{Name: name, Err: err}
	}
	p := &Process{cmd: cmd, process: cmd.Process, name: name, group: spec.Group}
	if spec.Group {
		p.tree = track(cmd.Process)
	}
	return p, nil
}

// Wait returns the child's exit code and an error that explains a failure.
// With a pseudo-terminal, it also waits for the child's last output and
// gives the terminal back.
func (p *Process) Wait() (int, error) {
	var state *os.ProcessState
	var err error
	if p.cmd != nil {
		err = p.cmd.Wait()
		state = p.cmd.ProcessState
	} else {
		state, err = p.process.Wait()
	}
	if p.console != nil {
		p.console.finish()
	}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return exit.ExitCode(), &ExitError{Code: exit.ExitCode()}
	case err != nil:
		return 1, &StartError{Name: p.name, Err: err}
	case state != nil && !state.Success():
		return state.ExitCode(), &ExitError{Code: state.ExitCode()}
	}
	return 0, nil
}

// Stop asks the child, and its process group when it has one, to exit. For a
// grouped child it also reaches processes the child started, even after the
// child itself has exited, so call it once a grouped child is no longer
// needed. Stop is not safe to call from several goroutines at once.
func (p *Process) Stop() {
	if p.process != nil {
		stopTree(p.process, p.group, &p.tree)
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
