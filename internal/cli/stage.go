package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

// Some programs want a path, not a value: a certificate, a credentials
// file, a configuration file with values in it. stage writes those files
// for one command, in a folder only the user can read, and gives the
// command their paths (docs/project-file.md). The folder is removed when
// the command ends.

// stageRoot is where the folders are made: in memory where the system
// offers that, else the temporary folder.
func stageRoot() string {
	if runtime.GOOS == "linux" {
		if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
			return "/dev/shm"
		}
	}
	return ""
}

var templateVariable = regexp.MustCompile(`\{\{\s*([A-Z_][A-Z0-9_]*)\s*\}\}`)

// renderTemplate fills in {{NAME}} with the value of each variable. A name
// the environment does not define is an error; anything else between
// braces is left alone, so templates of other tools pass through.
func renderTemplate(template []byte, values map[string][]byte) ([]byte, error) {
	var missing []string
	out := templateVariable.ReplaceAllFunc(template, func(match []byte) []byte {
		name := string(templateVariable.FindSubmatch(match)[1])
		value, ok := values[name]
		if !ok {
			missing = append(missing, name)
			return match
		}
		return value
	})
	if len(missing) > 0 {
		wipe(out)
		return nil, fmt.Errorf("the template uses %s, which the environment does not define", strings.Join(missing, ", "))
	}
	return out, nil
}

// stage returns the pairs a command receives: pairs, with the variables
// listed under files: holding the path of a file with their value, and one
// more for each template under render:. It returns the function that
// removes the files. With neither section it returns pairs as they are.
//
// extra are templates for this run only, as variable → path, which
// `envrune render` passes.
func (w Workspace) stage(projectPath string, pairs []runner.Pair, extra map[string]string) ([]runner.Pair, func(), error) {
	none := func() {}
	config, err := project.Load(projectPath)
	if err != nil {
		return pairs, none, nil
	}
	templates := map[string]string{}
	for variable, path := range config.Render {
		templates[variable] = filepath.Join(filepath.Dir(projectPath), filepath.FromSlash(path))
	}
	for variable, path := range extra {
		templates[variable] = path
	}
	if len(config.Files) == 0 && len(templates) == 0 {
		return pairs, none, nil
	}
	values := map[string][]byte{}
	for _, p := range pairs {
		values[p.Name] = p.Value
	}
	dir, err := os.MkdirTemp(stageRoot(), "envrune-")
	if err != nil {
		return nil, none, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	fail := func(err error) ([]runner.Pair, func(), error) {
		cleanup()
		return nil, none, err
	}
	write := func(name string, content []byte) (string, error) {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			path = filepath.Join(dir, fmt.Sprintf("%d-%s", len(values), name))
		}
		return path, os.WriteFile(path, content, 0600)
	}
	staged := make([]runner.Pair, 0, len(pairs)+len(templates))
	for _, p := range pairs {
		isFile := false
		for _, name := range config.Files {
			isFile = isFile || name == p.Name
		}
		if !isFile {
			staged = append(staged, runner.Pair{Name: p.Name, Value: bytes.Clone(p.Value)})
			continue
		}
		path, err := write(strings.ToLower(p.Name), p.Value)
		if err != nil {
			return fail(err)
		}
		staged = append(staged, runner.Pair{Name: p.Name, Value: []byte(path)})
	}
	for variable, source := range templates {
		template, err := os.ReadFile(source)
		if err != nil {
			return fail(fmt.Errorf("the template for %s could not be read: %s", variable, filepath.Base(source)))
		}
		rendered, err := renderTemplate(template, values)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", filepath.Base(source), err))
		}
		path, err := write(strings.TrimSuffix(filepath.Base(source), ".tmpl"), rendered)
		wipe(rendered)
		if err != nil {
			return fail(err)
		}
		// A template's variable replaces one of the same name.
		kept := staged[:0]
		for _, p := range staged {
			if p.Name != variable {
				kept = append(kept, p)
			}
		}
		staged = append(kept, runner.Pair{Name: variable, Value: []byte(path)})
	}
	return staged, func() {
		wipePairs(staged)
		cleanup()
	}, nil
}
