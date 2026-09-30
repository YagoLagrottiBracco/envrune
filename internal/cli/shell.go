package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

// Shell is a foreground interactive Envrune session. It never invokes a
// system shell and retains an opened vault only for the duration of Run.
type Shell struct {
	Input       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	ReadSecret  func(string) ([]byte, error)
	ReadChoice  func(string) (string, error)
	OpenSession func([]byte) (*app.Session, error)
	// Unlock, when set, replaces the master password prompt, so an agent or
	// the system keychain can open the session.
	Unlock      func() (*app.Session, error)
	FindProject func(string) (string, error)
	Environment func() []string
	StartUI     func(*app.Session, []string, io.Writer, io.Writer) int
	Interrupt   <-chan struct{}
	// Busy is set while a command runs, so Ctrl+C stops the command instead
	// of locking the session.
	Busy *atomic.Bool
}

func executeShell(stdout, stderr io.Writer) int {
	prompt := SecretPrompt{Output: stderr}
	status := NewPresenter(stdout, stderr, os.Getenv)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	interrupt := make(chan struct{})
	busy := &atomic.Bool{}
	go func() {
		for sig := range signals {
			if sig == syscall.SIGTERM || !busy.Load() {
				close(interrupt)
				return
			}
		}
	}()
	return Shell{
		Input:      os.Stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		ReadSecret: prompt.Read,
		ReadChoice: ChoicePrompt{Output: stderr}.Read,
		Unlock: func() (*app.Session, error) {
			return unlocker{getenv: os.Getenv, prompt: prompt.Read, status: status}.session()
		},
		FindProject: project.Find,
		Environment: os.Environ,
		StartUI:     executeSessionUI,
		Interrupt:   interrupt,
		Busy:        busy,
	}.Run()
}

func (s Shell) open() (*app.Session, error) {
	if s.Unlock != nil {
		return s.Unlock()
	}
	password, err := s.ReadSecret("Master password")
	if err != nil {
		return nil, err
	}
	defer wipe(password)
	return s.OpenSession(password)
}

func (s Shell) interrupted() bool {
	if s.Interrupt == nil {
		return false
	}
	select {
	case <-s.Interrupt:
		return true
	default:
		return false
	}
}

func (s Shell) Run() int {
	status := NewPresenter(s.Stdout, s.Stderr, os.Getenv)
	if s.Input == nil || s.Stdout == nil || s.Stderr == nil || s.ReadSecret == nil || (s.OpenSession == nil && s.Unlock == nil) {
		status.Error("Interactive shell is unavailable.")
		return 1
	}
	session, err := s.open()
	if err != nil {
		status.Error(describe(err, "Unable to unlock the vault."))
		return 1
	}
	defer session.Close()
	status.Success("Vault unlocked for this session.")
	workspace := Workspace{
		Session:     session,
		Stdout:      s.Stdout,
		Stderr:      s.Stderr,
		ReadSecret:  s.ReadSecret,
		ReadChoice:  s.ReadChoice,
		FindProject: s.FindProject,
		Environment: s.Environment,
		StartUI:     s.StartUI,
	}

	reader := bufio.NewReader(s.Input)
	for {
		_, _ = fmt.Fprint(s.Stdout, "envrune [unlocked] > ")
		if s.interrupted() {
			status.Success("Session locked.")
			return 130
		}
		line, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			if s.interrupted() {
				status.Success("Session locked.")
				return 130
			}
			status.Error("Session input is unavailable.")
			return 1
		}
		args, parseErr := parseShellLine(strings.TrimSuffix(line, "\n"))
		if parseErr != nil {
			status.Error("Invalid command syntax.")
		} else if len(args) > 0 {
			code, closeSession := s.execute(workspace, status, args)
			if closeSession {
				status.Success("Session locked.")
				return code
			}
		}
		if errors.Is(readErr, io.EOF) {
			status.Success("Session locked.")
			return 0
		}
	}
}

func (s Shell) execute(workspace Workspace, status Presenter, args []string) (int, bool) {
	switch args[0] {
	case "exit", "lock":
		if len(args) != 1 {
			status.Error("Invalid command arguments.")
			return 2, false
		}
		return 0, true
	case "help", "--help", "-h":
		fmt.Fprint(s.Stdout, helpText)
		fmt.Fprintln(s.Stdout, "\nIn this shell, `lock` or `exit` ends the session.")
		return 0, false
	}
	if s.Busy != nil {
		s.Busy.Store(true)
		defer s.Busy.Store(false)
	}
	return workspace.Execute(args), false
}

func parseShellLine(line string) ([]string, error) {
	var args []string
	var word strings.Builder
	var quote rune
	escaped, started := false, false
	flush := func() {
		if started {
			args = append(args, word.String())
			word.Reset()
			started = false
		}
	}
	for _, char := range line {
		if escaped {
			word.WriteRune(char)
			started, escaped = true, false
			continue
		}
		if char == '\\' && quote != '\'' {
			escaped, started = true, true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				word.WriteRune(char)
			}
			started = true
			continue
		}
		if char == '\'' || char == '"' {
			quote, started = char, true
			continue
		}
		if char == ' ' || char == '\t' || char == '\r' {
			flush()
			continue
		}
		word.WriteRune(char)
		started = true
	}
	if quote != 0 || escaped {
		return nil, errors.New("invalid command syntax")
	}
	flush()
	return args, nil
}
