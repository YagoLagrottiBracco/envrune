package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

// linkLocal maps a variable in the personal override next to envrune.yml,
// which is one developer's own and is kept out of Git.
func (w Workspace) linkLocal(projectPath, environment, variable, rawRef string) int {
	ref, err := domain.ParseReference(rawRef)
	if err != nil {
		return w.fail(err, "The reference is not valid.")
	}
	created, err := project.SetLocalBinding(projectPath, environment, variable, ref)
	if err != nil {
		return w.fail(err, "The personal override could not be written.")
	}
	w.status().Success(fmt.Sprintf("Linked %s to %s for environment %s, for you only, in %s.", variable, ref, environment, project.LocalFileName))
	if created {
		if ignored, err := ignoreLocal(filepath.Dir(projectPath)); err != nil {
			w.status().Warn(fmt.Sprintf("Add %s to .gitignore: it is yours alone.", project.LocalFileName))
		} else if ignored {
			w.status().Info(fmt.Sprintf("Added %s to .gitignore: it is yours alone.", project.LocalFileName))
		}
	}
	return 0
}

// ignoreLocal makes the .gitignore in dir list the personal override, and
// reports whether it had to add it.
func ignoreLocal(dir string) (bool, error) {
	path := filepath.Join(dir, ".gitignore")
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "/")) == project.LocalFileName {
			return false, nil
		}
	}
	text := string(raw)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return true, os.WriteFile(path, []byte(text+project.LocalFileName+"\n"), 0644)
}
