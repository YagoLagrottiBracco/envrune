package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/redact"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

// maxSecretFile bounds a file stored as a secret.
const maxSecretFile = 64 << 10

// readSecretFile reads a file to store its content as a secret.
func readSecretFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("the file could not be read: %s", filepath.Base(path))
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxSecretFile+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("the file could not be read: %s", filepath.Base(path))
	case len(value) == 0:
		return nil, fmt.Errorf("%s is empty", filepath.Base(path))
	case len(value) > maxSecretFile:
		wipe(value)
		return nil, fmt.Errorf("%s is larger than %d KiB, the most a secret holds", filepath.Base(path), maxSecretFile>>10)
	}
	return value, nil
}

// render fills in a template for one run and gives the command its path.
func (w Workspace) render(argv []string) int {
	const usage = "render <template> [--env <environment>] [--as <VAR>] [--no-redact] -- <command> [args...]"
	a, err := parseArgs(argv, []string{"env", "as"}, []string{"no-redact"}, false)
	if err != nil || len(a.positional) != 1 || len(a.rest) == 0 {
		return w.usageError(usage)
	}
	variable := a.options["as"]
	if variable == "" {
		variable = "ENVRUNE_RENDERED"
	}
	if !project.VariableName(variable) {
		return w.usageError(usage)
	}
	template, err := filepath.Abs(a.positional[0])
	if err != nil {
		return w.usageError(usage)
	}
	if _, err := os.Stat(template); err != nil {
		w.status().Error(fmt.Sprintf("The template %s was not found.", a.positional[0]))
		return 1
	}
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	w.freshen(projectPath, a.options["env"])
	proxied, stop, err := w.seal(projectPath, a.options["env"])
	defer stop()
	if err != nil {
		return w.cloudFail(err)
	}
	_, resolved, err := w.resolve(a.options["env"])
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	if !w.maySkipMasking(resolved, a.flags["no-redact"]) {
		return 1
	}
	noteUse(w.Session, projectPath, resolved)
	w.status().Info(fmt.Sprintf("Starting %s with %s filled in from %s; its path is in %s.", a.rest[0], filepath.Base(template), resolved.Environment, variable))
	watch := &rotationWatch{secrets: projectPath, environment: a.options["env"], extra: proxied, templates: map[string]string{variable: template}}
	return w.runWatching(runner.Spec{Command: a.rest, Additions: resolved.Pairs, Inherited: w.environ()}, !a.flags["no-redact"], watch)
}

// checkTimeout bounds one check, so a service that does not answer does not
// hold up the rest.
var checkTimeout = 60 * time.Second

// check runs the project's checks: commands that succeed while a secret
// still works. EnvRune does not know how to test a key of any service; the
// project says how (docs/project-file.md).
func (w Workspace) check(argv []string) int {
	a, err := parseArgs(argv, []string{"env"}, nil, false)
	if err != nil {
		return w.usageError("check [name...] [--env <environment>]")
	}
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	config, err := project.Load(projectPath)
	if err != nil {
		return w.fail(err, "The project configuration is invalid.")
	}
	names := a.positional
	if len(names) == 0 {
		for name := range config.Checks {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	if len(names) == 0 {
		w.status().Info("envrune.yml has no checks. Add them under checks:, as commands that succeed while a secret still works.")
		return 0
	}
	for _, name := range names {
		if _, ok := config.Checks[name]; !ok {
			w.status().Error(fmt.Sprintf("envrune.yml has no check named %s.", name))
			return 2
		}
	}
	w.freshen(projectPath, a.options["env"])
	proxied, stop, err := w.seal(projectPath, a.options["env"])
	defer stop()
	if err != nil {
		return w.cloudFail(err)
	}
	_, resolved, err := w.resolve(a.options["env"])
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	staged, cleanup, err := w.stage(projectPath, resolved.Pairs, nil)
	if err != nil {
		w.status().Error(sentence(strings.TrimRight(err.Error(), ".")))
		return 1
	}
	defer cleanup()
	given := append(staged, proxied...)
	matcher := pairMatcher(given)
	defer matcher.Wipe()

	failed := 0
	for _, name := range names {
		words, err := parseShellLine(config.Checks[name])
		if err != nil || len(words) == 0 {
			w.status().Error(fmt.Sprintf("checks.%s in envrune.yml has unbalanced quotes.", name))
			return 2
		}
		var output bytes.Buffer
		masked := redact.NewWriter(&output, matcher)
		process, err := runner.Start(runner.Spec{Command: words, Additions: given, Inherited: w.environ(), Dir: filepath.Dir(projectPath),
			Stdout: masked, Stderr: masked, Group: true})
		if err != nil {
			failed++
			w.status().Error(fmt.Sprintf("%s could not run: %s", name, describe(err, "the command was not found")))
			continue
		}
		done := make(chan int, 1)
		go func() {
			code, _ := process.Wait()
			done <- code
		}()
		var code int
		timedOut := false
		select {
		case code = <-done:
		case <-time.After(checkTimeout):
			timedOut = true
			process.Stop()
			code = <-done
		}
		process.Stop()
		_ = masked.Close()
		switch {
		case timedOut:
			failed++
			w.status().Error(fmt.Sprintf("%s did not finish in %s.", name, checkTimeout))
		case code != 0:
			failed++
			w.status().Error(fmt.Sprintf("%s failed (exit %d).", name, code))
			// What it said helps find out why; values in it are masked.
			if text := strings.TrimSpace(output.String()); text != "" {
				lines := strings.Split(text, "\n")
				for _, line := range lines[max(0, len(lines)-10):] {
					fmt.Fprintln(w.Stderr, "    "+line)
				}
			}
		default:
			w.status().Success(name + " passed.")
		}
	}
	if failed > 0 {
		w.status().Error(fmt.Sprintf("%d of %d %s failed in %s.", failed, len(names), plural(len(names), "check", "checks"), resolved.Environment))
		return 1
	}
	return 0
}
