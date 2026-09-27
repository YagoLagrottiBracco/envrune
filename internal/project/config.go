// Package project owns safe, versionable Envrune project configuration.
package project

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/envrune/envrune/internal/domain"
	"gopkg.in/yaml.v3"
)

var ErrInvalidConfig = errors.New("invalid project configuration")
var variableName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func VariableName(value string) bool { return variableName.MatchString(value) }

type Config struct {
	Version      int
	Project      string
	Environments map[string]map[string]domain.Reference
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	var node yaml.Node
	if yaml.Unmarshal(raw, &node) != nil || len(node.Content) != 1 {
		return Config{}, ErrInvalidConfig
	}
	return parseDocument(node.Content[0])
}

func parseDocument(root *yaml.Node) (Config, error) {
	if root.Kind != yaml.MappingNode || len(root.Content)%2 != 0 {
		return Config{}, ErrInvalidConfig
	}
	values := map[string]*yaml.Node{}
	for i := 0; i < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		if k.Kind != yaml.ScalarNode || values[k.Value] != nil {
			return Config{}, ErrInvalidConfig
		}
		values[k.Value] = v
	}
	if len(values) != 3 || values["version"] == nil || values["project"] == nil || values["environments"] == nil {
		return Config{}, ErrInvalidConfig
	}
	if values["version"].Kind != yaml.ScalarNode || values["version"].Tag != "!!int" || values["version"].Value != "1" || values["project"].Kind != yaml.ScalarNode || values["project"].Tag != "!!str" || values["project"].Value == "" {
		return Config{}, ErrInvalidConfig
	}
	envs := values["environments"]
	if envs.Kind != yaml.MappingNode || len(envs.Content)%2 != 0 {
		return Config{}, ErrInvalidConfig
	}
	out := Config{Version: 1, Project: values["project"].Value, Environments: map[string]map[string]domain.Reference{}}
	for i := 0; i < len(envs.Content); i += 2 {
		e, m := envs.Content[i], envs.Content[i+1]
		if e.Kind != yaml.ScalarNode || e.Tag != "!!str" || e.Value == "" || m.Kind != yaml.MappingNode || len(m.Content)%2 != 0 || out.Environments[e.Value] != nil {
			return Config{}, ErrInvalidConfig
		}
		vars := map[string]domain.Reference{}
		for j := 0; j < len(m.Content); j += 2 {
			k, v := m.Content[j], m.Content[j+1]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || v.Kind != yaml.ScalarNode || v.Tag != "!!str" || !variableName.MatchString(k.Value) || vars[k.Value] != "" {
				return Config{}, ErrInvalidConfig
			}
			ref, err := domain.ParseReference(v.Value)
			if err != nil {
				return Config{}, ErrInvalidConfig
			}
			vars[k.Value] = ref
		}
		out.Environments[e.Value] = vars
	}
	return out, nil
}

func WriteAtomic(path string, config Config) error {
	if config.Version != 1 || config.Project == "" || config.Environments == nil {
		return ErrInvalidConfig
	}
	for _, mappings := range config.Environments {
		for variable, ref := range mappings {
			if !variableName.MatchString(variable) {
				return ErrInvalidConfig
			}
			if _, err := domain.ParseReference(ref.String()); err != nil {
				return ErrInvalidConfig
			}
		}
	}
	raw, err := yaml.Marshal(struct {
		Version      int                                    `yaml:"version"`
		Project      string                                 `yaml:"project"`
		Environments map[string]map[string]domain.Reference `yaml:"environments"`
	}{1, config.Project, config.Environments})
	if err != nil {
		return ErrInvalidConfig
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".envrune-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err = tmp.Write(raw); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncParent(filepath.Dir(path))
}
