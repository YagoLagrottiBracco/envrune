package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/envrune/envrune/internal/app"
	"github.com/envrune/envrune/internal/dotenv"
	"github.com/envrune/envrune/internal/exporter"
	"github.com/envrune/envrune/internal/paths"
	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/runner"
)

func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		return executeOnboarding(stdout, stderr)
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "Usage: envrune <command>")
		fmt.Fprintln(stdout, "Commands: init, shell, set, list, link, usage, generate, import, run, export, ui")
		return 0
	}
	if args[0] == "ui" {
		return executeUI(args[1:], stdout, stderr)
	}
	if args[0] == "shell" {
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: envrune shell")
			return 2
		}
		return executeShell(stdout, stderr)
	}
	status := NewPresenter(stdout, stderr, os.Getenv)
	if args[0] == "set" && len(args) != 2 {
		fmt.Fprintln(stderr, "usage: envrune set <secret-reference>")
		return 2
	}
	if args[0] == "link" && (len(args) != 5 || args[3] != "--env") {
		fmt.Fprintln(stderr, "usage: envrune link <VAR> <reference> --env <environment>")
		return 2
	}
	if args[0] == "usage" && len(args) != 2 {
		fmt.Fprintln(stderr, "usage: envrune usage <reference>")
		return 2
	}
	if args[0] == "generate" && (len(args) != 4 || args[2] != "--length") {
		fmt.Fprintln(stderr, "usage: envrune generate <reference> --length <n>")
		return 2
	}
	if args[0] == "import" && len(args) != 2 {
		fmt.Fprintln(stderr, "usage: envrune import <file.env>")
		return 2
	}
	if args[0] == "run" && (len(args) < 5 || args[1] != "--env" || args[3] != "--") {
		fmt.Fprintln(stderr, "usage: envrune run --env <environment> -- <command>")
		return 2
	}
	if args[0] == "export" && (len(args) < 3 || args[1] != "--env") {
		fmt.Fprintln(stderr, "usage: envrune export --env <environment> [--output path] [--force]")
		return 2
	}
	if (args[0] == "init" || args[0] == "list") && len(args) != 1 {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	if args[0] != "init" && args[0] != "set" && args[0] != "list" && args[0] != "link" && args[0] != "usage" && args[0] != "generate" && args[0] != "import" && args[0] != "run" && args[0] != "export" {
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
	p := SecretPrompt{Output: stderr}
	password, err := p.Read("Master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	defer wipe(password)
	path, err := paths.VaultPath(os.Getenv, os.UserHomeDir)
	if err != nil {
		status.Error("Vault path is unavailable.")
		return 1
	}
	s := app.VaultService{}
	if args[0] == "init" {
		confirmation, e := p.Read("Confirm master password")
		if e != nil {
			status.Error(describe(e, "Secure interactive input is required."))
			return 1
		}
		defer wipe(confirmation)
		err = s.Init(path, password, confirmation)
	} else if args[0] == "set" {
		value, e := readConfirmedValue(p.Read, "Secret value")
		if e != nil {
			status.Error(describe(e, "Secure interactive input is required."))
			return 1
		}
		defer wipe(value)
		err = s.Set(path, password, args[1], value)
	} else if args[0] == "list" {
		var refs []string
		refs, err = s.List(path, password)
		for _, r := range refs {
			fmt.Fprintln(stdout, r)
		}
	} else if args[0] == "link" {
		projectPath, e := project.Find(".")
		if e != nil {
			status.Error("No Envrune project configuration was found.")
			return 1
		}
		err = s.Link(path, projectPath, args[4], args[1], args[2], password)
	} else if args[0] == "usage" {
		usages, e := s.Usage(path, args[1], password)
		err = e
		for _, usage := range usages {
			fmt.Fprintf(stdout, "%s %s %s\n", usage.ProjectPath, usage.Environment, usage.Variable)
		}
	} else if args[0] == "generate" {
		length, e := strconv.Atoi(args[3])
		if e != nil {
			fmt.Fprintln(stderr, "invalid generated value length")
			return 2
		}
		err = s.Generate(path, args[1], length, password)
	} else if args[0] == "import" {
		raw, e := os.ReadFile(args[1])
		if e != nil {
			status.Error("The import file is unavailable.")
			return 1
		}
		entries, e := dotenv.Parse(raw)
		if e != nil {
			status.Error("The dotenv input is invalid.")
			return 1
		}
		for _, entry := range entries {
			fmt.Fprintln(stdout, entry.Name)
		}
		if !confirm(stderr) {
			status.Error("Confirmation is required.")
			return 1
		}
		_, err = s.Import(path, entries, password)
	} else {
		projectPath, e := project.Find(".")
		if e != nil {
			status.Error("No Envrune project configuration was found.")
			return 1
		}
		var pairs []runner.Pair
		pairs, err = s.ResolveEnvironment(path, projectPath, args[2], password)
		defer wipePairs(pairs)
		if args[0] == "run" && err == nil {
			status.Info(fmt.Sprintf("Starting command with %d injected variables.", len(pairs)))
			code, runErr := runner.Run(args[4:], pairs, os.Environ(), stdout, stderr)
			if runErr != nil {
				status.Error(describe(runErr, "The command could not be run."))
			}
			return code
		}
		if args[0] == "export" && err == nil {
			output, force, e := exportArguments(args[3:], args[2])
			if e != nil {
				status.Error("Export arguments are invalid.")
				return 2
			}
			for _, pair := range pairs {
				fmt.Fprintln(stdout, pair.Name)
			}
			status.Warn("Export writes plaintext secrets. Delete the file after use.")
			if !confirm(stderr) {
				status.Error("Confirmation is required.")
				return 1
			}
			if insideGit(filepath.Dir(output)) && !confirm(stderr) {
				status.Error("Additional confirmation is required for a Git directory.")
				return 1
			}
			err = exporter.Write(output, pairs, force)
		}
	}
	if err != nil {
		status.Error(describe(err, "Command failed. Check your password, vault, and project configuration."))
		return 1
	}
	switch args[0] {
	case "init":
		status.Success("Vault initialized.")
	case "set":
		status.Success(fmt.Sprintf("Secret stored: %s", args[1]))
	case "list":
		status.Success("Secret references listed.")
	case "link":
		status.Success(fmt.Sprintf("Linked %s for environment %s.", args[1], args[4]))
	case "usage":
		status.Success("Secret usage listed.")
	case "generate":
		status.Success(fmt.Sprintf("Generated and stored a %s-character secret.", args[3]))
	case "import":
		status.Success("Secrets imported.")
	case "export":
		status.Success("Plaintext export created.")
	}
	return 0
}
func confirm(out io.Writer) bool {
	p := SecretPrompt{Output: out}
	value, err := p.Read("Type YES to confirm")
	if err != nil {
		return false
	}
	defer wipe(value)
	return string(value) == "YES"
}
func exportArguments(args []string, environment string) (string, bool, error) {
	if environment == "" || strings.ContainsAny(environment, "/\\") || environment == "." || environment == ".." {
		return "", false, fmt.Errorf("bad")
	}
	output := filepath.Join(".", ".env."+environment)
	force := false
	for len(args) > 0 {
		switch args[0] {
		case "--force":
			force = true
			args = args[1:]
		case "--output":
			if len(args) < 2 {
				return "", false, fmt.Errorf("bad")
			}
			output = args[1]
			args = args[2:]
		default:
			return "", false, fmt.Errorf("bad")
		}
	}
	return output, force, nil
}
func insideGit(dir string) bool {
	return exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run() == nil
}
func wipePairs(pairs []runner.Pair) {
	for _, pair := range pairs {
		wipe(pair.Value)
	}
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
