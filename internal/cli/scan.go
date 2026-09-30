package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/redact"
)

// skippedDirs are folders scan does not walk into: Git's own data, which
// the history scan covers, and dependency folders nobody commits.
var skippedDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true}

// place is where scan found a value.
type place struct {
	Name  string // the reference
	Where string // path:line, or the commit and path:line
}

// scan looks for vault values in files and in Git history.
func (w Workspace) scan(argv []string) int {
	const usage = "scan [path...] [--no-history]"
	a, err := parseArgs(argv, nil, []string{"no-history"}, false)
	if err != nil {
		return w.usageError(usage)
	}
	roots := a.positional
	if len(roots) == 0 {
		roots = []string{"."}
	}
	secrets, err := w.Session.Secrets(w.projectPathOrEmpty())
	if err != nil {
		return w.fail(err, "The vault could not be read.")
	}
	matcher := redact.NewMatcher(secrets)
	for _, secret := range secrets {
		wipe(secret.Value)
	}
	defer matcher.Wipe()
	status := NewPresenter(w.Stdout, w.Stdout, os.Getenv) // one report, in order

	var places []place
	files := 0
	for _, root := range roots {
		found, n, err := scanFiles(root, matcher)
		if err != nil {
			return w.fail(err, "Could not read "+root+".")
		}
		places, files = append(places, found...), files+n
	}
	history := ""
	if !a.flags["no-history"] {
		if dir := historyDir(roots[0]); dir != "" {
			found, commits, err := scanHistory(dir, matcher)
			if err != nil {
				status.Warn("Git history was not scanned: " + err.Error())
			} else {
				places = append(places, found...)
				history = fmt.Sprintf(" and %d commits", commits)
			}
		}
	}
	if len(places) == 0 {
		status.Success(fmt.Sprintf("No vault values found in %d files%s.", files, history))
		return 0
	}
	byName := map[string][]string{}
	for _, p := range places {
		byName[p.Name] = append(byName[p.Name], p.Where)
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		status.Error(fmt.Sprintf("%s appears in %d %s:", name, len(byName[name]), plural(len(byName[name]), "place", "places")))
		for _, where := range byName[name] {
			fmt.Fprintln(w.Stdout, "  "+where)
		}
	}
	status.Warn(fmt.Sprintf("Found %d %s in %d files%s. Rotate each value that may have left this machine (`envrune rotate <reference>` or at its provider); removing it from files or history does not make it secret again.",
		len(names), plural(len(names), "leaked value", "leaked values"), files, history))
	return 1
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// scanFiles searches root, a file or a folder, and returns what it found and
// how many files it read. Files with NUL bytes in their first 8 KiB are
// treated as binary and skipped.
func scanFiles(root string, matcher *redact.Matcher) ([]place, int, error) {
	var out []place
	files := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return nil // unreadable entries below root are skipped
		}
		if entry.IsDir() {
			if path != root && skippedDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		reader := bufio.NewReaderSize(file, 8192)
		if head, _ := reader.Peek(8192); bytes.IndexByte(head, 0) >= 0 {
			return nil
		}
		files++
		display := filepath.ToSlash(path)
		return matcher.Scan(reader, func(name string, line int) {
			out = append(out, place{Name: name, Where: fmt.Sprintf("%s:%d", display, line)})
		})
	})
	return out, files, err
}

// historyDir returns the top of the Git repository that contains path, or
// "" when there is none.
func historyDir(path string) string {
	dir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// commitMarker starts each commit in the log that scanHistory reads; a diff
// line always starts with another character.
const commitMarker = "\x00envrune-commit "

// scanHistory searches what every commit on every branch added.
func scanHistory(dir string, matcher *redact.Matcher) ([]place, int, error) {
	cmd := exec.Command("git", "-C", dir, "-c", "core.quotePath=false", "log", "--all", "-p", "--no-color", "--no-ext-diff",
		"--unified=0", "--date=short", "--format="+strings.ReplaceAll(commitMarker, "\x00", "%x00")+"%h %ad %an")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, 0, err
	}
	var out []place
	commits := 0
	var header string
	var diff bytes.Buffer
	flush := func() {
		if header != "" {
			for _, l := range findInDiff(diff.Bytes(), matcher) {
				out = append(out, place{Name: l.Name, Where: fmt.Sprintf("commit %s: %s:%d", header, l.File, l.Line)})
			}
		}
		wipe(diff.Bytes())
		diff.Reset()
	}
	reader := bufio.NewReaderSize(stdout, 1<<16)
	for {
		line, err := reader.ReadBytes('\n')
		if rest, ok := bytes.CutPrefix(line, []byte(commitMarker)); ok {
			flush()
			commits++
			fields := strings.SplitN(strings.TrimSpace(string(rest)), " ", 3)
			header = strings.Join(fields, " ")
			if len(fields) == 3 {
				header = fmt.Sprintf("%s (%s, %s)", fields[0], fields[1], fields[2])
			}
		} else {
			diff.Write(line)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = cmd.Process.Kill()
			return nil, 0, err
		}
	}
	flush()
	if err := cmd.Wait(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, 0, fmt.Errorf("%s", message)
		}
		return nil, 0, err
	}
	return out, commits, nil
}
