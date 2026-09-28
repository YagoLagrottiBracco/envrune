package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"strconv"

	"github.com/envrune/envrune/internal/app"
	"github.com/envrune/envrune/internal/dotenv"
	"github.com/envrune/envrune/internal/exporter"
	"github.com/envrune/envrune/internal/paths"
	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/runner"
)

func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: envrune <command>")
		return 2
	}
	if args[0] == "ui" { return executeUI(args[1:], stdout, stderr) }
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
	if args[0] == "generate" && (len(args) != 4 || args[2] != "--length") { fmt.Fprintln(stderr, "usage: envrune generate <reference> --length <n>"); return 2 }
	if args[0] == "import" && len(args) != 2 { fmt.Fprintln(stderr, "usage: envrune import <file.env>"); return 2 }
	if args[0] == "run" && (len(args) < 5 || args[1] != "--env" || args[3] != "--") { fmt.Fprintln(stderr, "usage: envrune run --env <environment> -- <command>"); return 2 }
	if args[0] == "export" && (len(args) < 3 || args[1] != "--env") { fmt.Fprintln(stderr, "usage: envrune export --env <environment> [--output path] [--force]"); return 2 }
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
		fmt.Fprintln(stderr, "secure interactive input is required")
		return 1
	}
	defer wipe(password)
	path, err := paths.VaultPath(os.Getenv, os.UserHomeDir)
	if err != nil {
		fmt.Fprintln(stderr, "vault path unavailable")
		return 1
	}
	s := app.VaultService{}
	if args[0] == "init" {
		confirmation, e := p.Read("Confirm master password")
		if e != nil {
			fmt.Fprintln(stderr, "secure interactive input is required")
			return 1
		}
		defer wipe(confirmation)
		err = s.Init(path, password, confirmation)
	} else if args[0] == "set" {
		value, e := p.Read("Secret value")
		if e != nil {
			fmt.Fprintln(stderr, "secure interactive input is required")
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
			fmt.Fprintln(stderr, "envrune project not found")
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
		length, e := strconv.Atoi(args[3]); if e != nil { fmt.Fprintln(stderr, "invalid generated value length"); return 2 }; err = s.Generate(path, args[1], length, password)
	} else if args[0] == "import" {
		raw, e := os.ReadFile(args[1]); if e != nil { fmt.Fprintln(stderr, "import file unavailable"); return 1 }; entries, e := dotenv.Parse(raw); if e != nil { fmt.Fprintln(stderr, "invalid dotenv input"); return 1 }
		for _, entry := range entries { fmt.Fprintln(stdout, entry.Name) }; if !confirm(stderr) { fmt.Fprintln(stderr, "confirmation required"); return 1 }; _, err = s.Import(path, entries, password)
	} else {
		projectPath, e := project.Find("."); if e != nil { fmt.Fprintln(stderr, "envrune project not found"); return 1 }
		var pairs []runner.Pair
		pairs, err = s.ResolveEnvironment(path, projectPath, args[2], password)
		defer wipePairs(pairs)
		if args[0] == "run" && err == nil { code, runErr := runner.Run(args[4:], pairs, os.Environ(), stdout, stderr); if runErr != nil { return code }; return code }
		if args[0] == "export" && err == nil { output, force, e := exportArguments(args[3:], args[2]); if e != nil { fmt.Fprintln(stderr, "invalid export arguments"); return 2 }; for _, pair := range pairs { fmt.Fprintln(stdout, pair.Name) }; fmt.Fprintln(stderr, "export writes plaintext; delete it manually after use"); if !confirm(stderr) { fmt.Fprintln(stderr, "confirmation required"); return 1 }; if insideGit(filepath.Dir(output)) && !confirm(stderr) { fmt.Fprintln(stderr, "additional git confirmation required"); return 1 }; err = exporter.Write(output, pairs, force) }
	}
	if err != nil {
		fmt.Fprintln(stderr, "command failed")
		return 1
	}
	return 0
}
func confirm(out io.Writer) bool { p := SecretPrompt{Output: out}; value, err := p.Read("Type YES to confirm"); if err != nil { return false }; defer wipe(value); return string(value) == "YES" }
func exportArguments(args []string, environment string) (string, bool, error) { if environment == "" || strings.ContainsAny(environment, "/\\") || environment == "." || environment == ".." { return "", false, fmt.Errorf("bad") }; output := filepath.Join(".", ".env."+environment); force := false; for len(args) > 0 { switch args[0] { case "--force": force = true; args = args[1:]; case "--output": if len(args) < 2 { return "", false, fmt.Errorf("bad") }; output = args[1]; args = args[2:]; default: return "", false, fmt.Errorf("bad") } }; return output, force, nil }
func insideGit(dir string) bool { return exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run() == nil }
func wipePairs(pairs []runner.Pair) { for _, pair := range pairs { wipe(pair.Value) } }
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
