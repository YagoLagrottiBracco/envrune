package runner

import (
	"errors"
	"io"
	"os/exec"
	"strings"
)

var ErrInvalidCommand = errors.New("invalid child command")
var ErrChildFailed = errors.New("child process failed")

func Run(command []string, additions []Pair, inherited []string, stdout, stderr io.Writer) (int, error) {
	if len(command) == 0 || command[0] == "" { return 2, ErrInvalidCommand }
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = extendEnvironment(inherited, additions)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	configureChild(cmd)
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok { return exit.ExitCode(), ErrChildFailed }
		return 1, ErrChildFailed
	}
	return 0, nil
}

func extendEnvironment(inherited []string, additions []Pair) []string {
	values := make(map[string]string, len(inherited)+len(additions))
	for _, entry := range inherited { if key, value, ok := strings.Cut(entry, "="); ok { values[key] = value } }
	for _, addition := range additions { values[addition.Name] = string(addition.Value) }
	result := make([]string, 0, len(values))
	for key, value := range values { result = append(result, key+"="+value) }
	return result
}
