package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

func Run(command []string, additions []Pair, inherited []string, stdout, stderr io.Writer) (int, error) {
	if len(command) == 0 || command[0] == "" {
		return 2, ErrInvalidCommand
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return 127, &CommandNotFoundError{Name: command[0]}
	}
	cmd, err := childCommand(path, command)
	if err != nil {
		return 1, &StartError{Name: command[0], Err: err}
	}
	cmd.Env = extendEnvironment(inherited, additions)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	configureChild(cmd)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), &ExitError{Code: exit.ExitCode()}
		}
		return 1, &StartError{Name: command[0], Err: err}
	}
	return 0, nil
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
