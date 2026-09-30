package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/redact"
)

// hookMarker identifies a pre-commit hook written by `envrune guard install`.
const hookMarker = "# envrune guard:"

// guard checks staged changes for vault values before a commit.
type guard struct {
	dir    string // where git runs; empty means the current directory
	getenv func(string) string
	stdout io.Writer
	stderr io.Writer
}

func executeGuard(args []string, stdout, stderr io.Writer) int {
	return guard{getenv: os.Getenv, stdout: stdout, stderr: stderr}.run(args)
}

func (g guard) run(args []string) int {
	status := NewPresenter(g.stdout, g.stderr, g.getenv)
	if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall") {
		if len(args) != 1 {
			fmt.Fprintf(g.stderr, "usage: envrune guard %s\n", args[0])
			return 2
		}
		if args[0] == "install" {
			return g.install(status)
		}
		return g.uninstall(status)
	}
	a, err := parseArgs(args, nil, []string{"strict"}, false)
	if err != nil || len(a.positional) != 0 {
		fmt.Fprintln(g.stderr, "usage: envrune guard [--strict] | guard install | guard uninstall")
		return 2
	}
	root, err := g.git("rev-parse", "--show-toplevel")
	if err != nil {
		status.Error("envrune guard runs inside a Git repository.")
		return 2
	}
	root = strings.TrimSpace(root)
	diff, err := g.git("-c", "core.quotePath=false", "diff", "--cached", "--no-color", "--no-ext-diff", "--unified=0", "--diff-filter=ACMR")
	if err != nil {
		status.Error("git diff --cached failed: " + err.Error())
		return 2
	}
	if strings.TrimSpace(diff) == "" {
		return 0
	}

	// A hook must never wait for a password, so only the environment, the
	// agent, and the keychain can unlock here.
	session, err := unlocker{getenv: g.getenv, noPrompt: true, status: status}.session()
	if err != nil {
		if a.flags["strict"] {
			status.Error("The staged changes were not checked: " + describe(err, "the vault is locked.") + " Run `envrune unlock` first.")
			return 1
		}
		status.Warn("The staged changes were not checked for vault values because the vault is locked. Run `envrune unlock` to check them.")
		return 0
	}
	defer session.Close()
	projectPath, _ := project.Find(root)
	secrets, err := session.Secrets(projectPath)
	if err != nil {
		status.Error(describe(err, "The vault could not be read."))
		return 1
	}
	matcher := redact.NewMatcher(secrets)
	for _, secret := range secrets {
		wipe(secret.Value)
	}
	defer matcher.Wipe()

	leaks := findInDiff([]byte(diff), matcher)
	if len(leaks) == 0 {
		return 0
	}
	for _, leak := range leaks {
		status.Error(fmt.Sprintf("%s:%d contains the value of %s", leak.File, leak.Line, leak.Name))
	}
	noun := "value is"
	if len(leaks) > 1 {
		noun = "values are"
	}
	status.Error(fmt.Sprintf("Commit blocked: %d vault %s staged. Remove them and use the reference through envrune.yml instead, or bypass this check once with `git commit --no-verify`.", len(leaks), noun))
	return 1
}

// leak is one occurrence of a vault value in a file.
type leak struct {
	File string
	Line int
	Name string
}

// findInDiff looks for values in the lines a unified diff adds. The added
// lines of each file are searched together, so a value that spans several
// lines, such as a PEM key, is found too.
func findInDiff(diff []byte, matcher *redact.Matcher) []leak {
	var out []leak
	seen := map[leak]bool{}
	var file string
	var next int
	var blob []byte
	var starts, numbers []int
	flush := func() {
		for _, match := range matcher.Find(blob) {
			i := sort.SearchInts(starts, match.Start+1) - 1
			l := leak{File: file, Line: numbers[i], Name: match.Name}
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
		wipe(blob)
		blob, starts, numbers = blob[:0], starts[:0], numbers[:0]
	}
	for _, line := range bytes.Split(diff, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		switch {
		case bytes.HasPrefix(line, []byte("diff --git ")):
			flush()
			file = ""
		case bytes.HasPrefix(line, []byte("+++ ")):
			file = diffPath(string(line[4:]))
		case bytes.HasPrefix(line, []byte("@@ ")):
			next = hunkStart(string(line))
		case bytes.HasPrefix(line, []byte("+")) && file != "":
			starts = append(starts, len(blob))
			numbers = append(numbers, next)
			blob = append(append(blob, line[1:]...), '\n')
			next++
		case bytes.HasPrefix(line, []byte(" ")):
			next++
		}
	}
	flush()
	return out
}

// diffPath turns the path of a "+++" line into a repository path.
func diffPath(raw string) string {
	if raw == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(raw, `"`) {
		if unquoted, err := strconv.Unquote(raw); err == nil {
			raw = unquoted
		}
	}
	return strings.TrimPrefix(raw, "b/")
}

// hunkStart reads the first new line number from "@@ -a,b +c,d @@".
func hunkStart(header string) int {
	fields := strings.Fields(header)
	if len(fields) < 3 || !strings.HasPrefix(fields[2], "+") {
		return 0
	}
	start, _, _ := strings.Cut(fields[2][1:], ",")
	n, _ := strconv.Atoi(start)
	return n
}

func (g guard) git(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return "", errors.New(message)
		}
		return "", err
	}
	return string(out), nil
}

// hookPath returns the pre-commit hook of the repository, honoring
// core.hooksPath.
func (g guard) hookPath() (string, error) {
	out, err := g.git("rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", err
	}
	dir := strings.TrimSpace(out)
	if !filepath.IsAbs(dir) {
		base := g.dir
		if base == "" {
			base, _ = os.Getwd()
		}
		dir = filepath.Join(base, dir)
	}
	return filepath.Join(dir, "pre-commit"), nil
}

func (g guard) install(status Presenter) int {
	hook, err := g.hookPath()
	if err != nil {
		status.Error("envrune guard install runs inside a Git repository.")
		return 2
	}
	if existing, err := os.ReadFile(hook); err == nil && !bytes.Contains(existing, []byte(hookMarker)) {
		status.Error(fmt.Sprintf("%s already exists and was not written by EnvRune. Add a line that runs `envrune guard` to it, or add EnvRune to your hook manager (see docs/guard.md).", hook))
		return 1
	}
	command := "envrune"
	if _, err := exec.LookPath("envrune"); err != nil {
		if self, err := os.Executable(); err == nil {
			command = filepath.ToSlash(self)
		}
	}
	script := "#!/bin/sh\n" +
		hookMarker + " blocks commits that contain vault values.\n" +
		"# Remove it with `envrune guard uninstall`; bypass it once with `git commit --no-verify`.\n" +
		"exec " + shellQuote(command) + " guard\n"
	if err := os.MkdirAll(filepath.Dir(hook), 0755); err != nil {
		status.Error(err.Error())
		return 1
	}
	if err := os.WriteFile(hook, []byte(script), 0755); err != nil {
		status.Error(err.Error())
		return 1
	}
	status.Success(fmt.Sprintf("Installed %s. Commits that stage a vault value are now blocked.", hook))
	return 0
}

func (g guard) uninstall(status Presenter) int {
	hook, err := g.hookPath()
	if err != nil {
		status.Error("envrune guard uninstall runs inside a Git repository.")
		return 2
	}
	existing, err := os.ReadFile(hook)
	if err != nil || !bytes.Contains(existing, []byte(hookMarker)) {
		status.Error("No pre-commit hook written by EnvRune was found.")
		return 1
	}
	if err := os.Remove(hook); err != nil {
		status.Error(err.Error())
		return 1
	}
	status.Success("Removed the EnvRune pre-commit hook.")
	return 0
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
