package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/dotenv"
	"github.com/YagoLagrottiBracco/envrune/internal/exporter"
	"github.com/YagoLagrottiBracco/envrune/internal/paths"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

// Shell is a foreground interactive Envrune session. It never invokes a
// system shell and retains an opened vault only for the duration of Run.
type Shell struct {
	Input       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	ReadSecret  func(string) ([]byte, error)
	OpenSession func([]byte) (*app.Session, error)
	FindProject func(string) (string, error)
	Environment func() []string
	StartUI     func(*app.Session, []string, io.Writer, io.Writer) int
	Interrupt   <-chan struct{}
}

func executeShell(stdout, stderr io.Writer) int {
	prompt := SecretPrompt{Output: stderr}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Shell{
		Input:      os.Stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		ReadSecret: prompt.Read,
		OpenSession: func(password []byte) (*app.Session, error) {
			path, err := paths.VaultPath(os.Getenv, os.UserHomeDir)
			if err != nil {
				return nil, err
			}
			return app.OpenSession(path, password)
		},
		FindProject: project.Find,
		Environment: os.Environ,
		StartUI:     executeSessionUI,
		Interrupt:   ctx.Done(),
	}.Run()
}

func (s Shell) Run() int {
	status := NewPresenter(s.Stdout, s.Stderr, os.Getenv)
	if s.Input == nil || s.Stdout == nil || s.Stderr == nil || s.ReadSecret == nil || s.OpenSession == nil {
		status.Error("Interactive shell is unavailable.")
		return 1
	}
	password, err := s.ReadSecret("Master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	session, err := s.OpenSession(password)
	wipe(password)
	if err != nil {
		status.Error(describe(err, "Unable to unlock the vault."))
		return 1
	}
	defer session.Close()
	status.Success("Vault unlocked for this session.")

	reader := bufio.NewReader(s.Input)
	for {
		_, _ = fmt.Fprint(s.Stdout, "envrune [unlocked] > ")
		if s.Interrupt != nil {
			select {
			case <-s.Interrupt:
				status.Success("Session locked.")
				return 130
			default:
			}
		}
		line, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			if s.Interrupt != nil {
				select {
				case <-s.Interrupt:
					status.Success("Session locked.")
					return 130
				default:
				}
			}
			status.Error("Session input is unavailable.")
			return 1
		}
		args, parseErr := parseShellLine(strings.TrimSuffix(line, "\n"))
		if parseErr != nil {
			status.Error("Invalid command syntax.")
		} else if len(args) > 0 {
			code, closeSession := s.execute(session, status, args)
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

func (s Shell) execute(session *app.Session, status Presenter, args []string) (int, bool) {
	command := args[0]
	if command == "exit" || command == "lock" {
		if len(args) != 1 {
			status.Error("Invalid command arguments.")
			return 2, false
		}
		return 0, true
	}
	if command == "help" || command == "--help" || command == "-h" {
		fmt.Fprintln(s.Stdout, "Commands: set, list, link, usage, generate, import, run, export, ui, lock, exit")
		return 0, false
	}
	switch command {
	case "set":
		if len(args) != 2 {
			status.Error("Usage: set <secret-reference>")
			return 2, false
		}
		value, err := readConfirmedValue(s.ReadSecret, "Secret value")
		if err == nil {
			err = session.Set(args[1], value)
		}
		wipe(value)
		if err != nil {
			status.Error(describe(err, "Secret could not be stored."))
			return 1, false
		}
		status.Success(fmt.Sprintf("Secret stored: %s", args[1]))
	case "list":
		if len(args) != 1 {
			status.Error("Usage: list")
			return 2, false
		}
		refs, err := session.List()
		if err != nil {
			status.Error(describe(err, "Secret references are unavailable."))
			return 1, false
		}
		for _, ref := range refs {
			fmt.Fprintln(s.Stdout, ref)
		}
		status.Success("Secret references listed.")
	case "link":
		if len(args) != 5 || args[3] != "--env" {
			status.Error("Usage: link <VAR> <reference> --env <environment>")
			return 2, false
		}
		projectPath, err := s.findProject()
		if err == nil {
			err = session.Link(projectPath, args[4], args[1], args[2])
		}
		if err != nil {
			status.Error(describe(err, "The project link could not be created."))
			return 1, false
		}
		status.Success(fmt.Sprintf("Linked %s for environment %s.", args[1], args[4]))
	case "usage":
		if len(args) != 2 {
			status.Error("Usage: usage <reference>")
			return 2, false
		}
		usages, err := session.Usage(args[1])
		if err != nil {
			status.Error(describe(err, "Secret usage is unavailable."))
			return 1, false
		}
		for _, usage := range usages {
			fmt.Fprintf(s.Stdout, "%s %s %s\n", usage.ProjectPath, usage.Environment, usage.Variable)
		}
		status.Success("Secret usage listed.")
	case "generate":
		if len(args) != 4 || args[2] != "--length" {
			status.Error("Usage: generate <reference> --length <n>")
			return 2, false
		}
		length, err := strconv.Atoi(args[3])
		if err == nil {
			err = session.Generate(args[1], length)
		}
		if err != nil {
			status.Error(describe(err, "Secret generation failed."))
			return 1, false
		}
		status.Success(fmt.Sprintf("Generated and stored a %d-character secret.", length))
	case "import":
		if len(args) != 2 {
			status.Error("Usage: import <file.env>")
			return 2, false
		}
		raw, err := os.ReadFile(args[1])
		if err == nil {
			entries, parseErr := dotenv.Parse(raw)
			if parseErr != nil {
				err = parseErr
			} else {
				for _, entry := range entries {
					fmt.Fprintln(s.Stdout, entry.Name)
				}
				if !s.confirm() {
					status.Error("Confirmation is required.")
					return 1, false
				}
				_, err = session.Import(entries)
			}
		}
		if err != nil {
			status.Error(describe(err, "Secrets could not be imported."))
			return 1, false
		}
		status.Success("Secrets imported.")
	case "run", "export":
		return s.executeRuntimeCommand(session, status, args)
	case "ui":
		start := s.StartUI
		if start == nil {
			start = executeSessionUI
		}
		return start(session, args[1:], s.Stdout, s.Stderr), false
	default:
		status.Error("Unknown command.")
		return 2, false
	}
	return 0, false
}

func (s Shell) executeRuntimeCommand(session *app.Session, status Presenter, args []string) (int, bool) {
	if len(args) < 3 || args[1] != "--env" {
		status.Error("Usage: run|export --env <environment> ...")
		return 2, false
	}
	projectPath, err := s.findProject()
	if err != nil {
		status.Error("No Envrune project configuration was found.")
		return 1, false
	}
	pairs, err := session.ResolveEnvironment(projectPath, args[2])
	defer wipePairs(pairs)
	if err != nil {
		status.Error(describe(err, "Configured secrets are unavailable."))
		return 1, false
	}
	if args[0] == "run" {
		if len(args) < 5 || args[3] != "--" {
			status.Error("Usage: run --env <environment> -- <command>")
			return 2, false
		}
		status.Info(fmt.Sprintf("Starting command with %d injected variables.", len(pairs)))
		environment := s.Environment
		if environment == nil {
			environment = os.Environ
		}
		code, runErr := runner.Run(args[4:], pairs, environment(), s.Stdout, s.Stderr)
		if runErr != nil {
			status.Error(describe(runErr, "The command could not be run."))
		}
		return code, false
	}
	output, force, err := exportArguments(args[3:], args[2])
	if err != nil {
		status.Error("Export arguments are invalid.")
		return 2, false
	}
	for _, pair := range pairs {
		fmt.Fprintln(s.Stdout, pair.Name)
	}
	status.Warn("Export writes plaintext secrets. Delete the file after use.")
	if !s.confirm() {
		status.Error("Confirmation is required.")
		return 1, false
	}
	if insideGit(filepath.Dir(output)) && !s.confirm() {
		status.Error("Additional confirmation is required for a Git directory.")
		return 1, false
	}
	if err := exporter.Write(output, pairs, force); err != nil {
		status.Error(describe(err, "Plaintext export could not be created."))
		return 1, false
	}
	status.Success("Plaintext export created.")
	return 0, false
}

func (s Shell) findProject() (string, error) {
	if s.FindProject == nil {
		return project.Find(".")
	}
	return s.FindProject(".")
}

func (s Shell) confirm() bool {
	value, err := s.ReadSecret("Type YES to confirm")
	if err != nil {
		return false
	}
	defer wipe(value)
	return string(value) == "YES"
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
