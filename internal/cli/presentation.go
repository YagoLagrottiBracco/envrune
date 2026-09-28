package cli

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiBlue   = "\x1b[34m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
)

var terminalWriter = func(writer any) bool {
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

// Presenter writes user-safe, English status messages. Styling is never used
// for redirected output so commands remain safe to script and test.
type Presenter struct {
	stdout      io.Writer
	stderr      io.Writer
	stdoutColor bool
	stderrColor bool
}

func NewPresenter(stdout, stderr io.Writer, getenv func(string) string) Presenter {
	if getenv == nil {
		getenv = os.Getenv
	}
	color := getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
	return Presenter{
		stdout:      stdout,
		stderr:      stderr,
		stdoutColor: color && terminalWriter(stdout),
		stderrColor: color && terminalWriter(stderr),
	}
}

func (p Presenter) Success(message string) {
	p.write(p.stdout, p.stdoutColor, ansiGreen, "OK", message)
}
func (p Presenter) Info(message string) { p.write(p.stdout, p.stdoutColor, ansiBlue, "INFO", message) }
func (p Presenter) Warn(message string) {
	p.write(p.stdout, p.stdoutColor, ansiYellow, "WARNING", message)
}
func (p Presenter) Error(message string) { p.write(p.stderr, p.stderrColor, ansiRed, "ERROR", message) }

func (p Presenter) write(writer io.Writer, color bool, code, label, message string) {
	if color {
		_, _ = fmt.Fprintf(writer, "%s[%s]%s %s\n", code, label, ansiReset, message)
		return
	}
	_, _ = fmt.Fprintf(writer, "[%s] %s\n", label, message)
}
