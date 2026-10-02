package project

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
)

// LocalFileName is one developer's own choices, next to envrune.yml and
// kept out of Git (docs/project-file.md).
const LocalFileName = "envrune.local.yml"

type environments = map[string]map[string]domain.Reference

// parseStrings reads a mapping of names to non-empty strings.
func parseStrings(node *yaml.Node, what string) (map[string]string, error) {
	pairs, err := mappingPairs(node, what)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, pair := range pairs {
		if out[pair[0].Value], err = stringValue(pair[1], what+"."+pair[0].Value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseVariableList reads a list of variable names.
func parseVariableList(node *yaml.Node, what string) ([]string, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, configError(node, "%s must be a list of variable names", what)
	}
	var out []string
	for _, item := range node.Content {
		name, err := stringValue(item, what)
		if err != nil {
			return nil, err
		}
		if !variableName.MatchString(name) {
			return nil, configError(item, "%s: %q is not a valid variable name; use names like API_KEY", what, name)
		}
		if slices.Contains(out, name) {
			return nil, configError(item, "%s lists %s twice", what, name)
		}
		out = append(out, name)
	}
	return out, nil
}

// layer turns the environments as written in the file at path into what
// each one resolves: the workspace root's, then the parents' (extends), then
// its own, then the personal override. root is false while loading a
// workspace root, which may not have one of its own.
func (c *Config) layer(path string, root bool) error {
	declared := c.Environments
	base := environments{}
	if c.Workspace != "" {
		if !root {
			return &ConfigError{Message: "a workspace root cannot have a workspace of its own"}
		}
		rootPath := filepath.Join(filepath.Dir(path), c.Workspace, filepath.Base(path))
		raw, err := os.ReadFile(rootPath)
		if err != nil {
			return &ConfigError{Message: fmt.Sprintf("workspace %s has no %s", c.Workspace, filepath.Base(path))}
		}
		var node yaml.Node
		if yaml.Unmarshal(raw, &node) != nil || len(node.Content) != 1 {
			return &ConfigError{Message: fmt.Sprintf("the workspace's %s is not valid YAML", filepath.Base(path))}
		}
		parent, err := parseDocument(node.Content[0])
		if err != nil {
			return fmt.Errorf("the workspace's %s: %w", filepath.Base(path), err)
		}
		if err := parent.layer(rootPath, false); err != nil {
			return fmt.Errorf("the workspace's %s: %w", filepath.Base(path), err)
		}
		base = parent.shared
		if c.Cloud == "" {
			c.Cloud, c.inheritedCloud = parent.Cloud, parent.Cloud != ""
		}
	}
	for child, parent := range c.Extends {
		if declared[child] == nil {
			return &ConfigError{Message: fmt.Sprintf("extends names %q, which is not an environment", child)}
		}
		if declared[parent] == nil && base[parent] == nil {
			return &ConfigError{Message: fmt.Sprintf("%s extends %q, which is not an environment", child, parent)}
		}
	}
	names := map[string]bool{}
	for name := range declared {
		names[name] = true
	}
	for name := range base {
		names[name] = true
	}
	c.shared, c.parent = environments{}, environments{}
	var resolve func(name string, visiting []string) (map[string]domain.Reference, error)
	resolve = func(name string, visiting []string) (map[string]domain.Reference, error) {
		if done, ok := c.shared[name]; ok {
			return done, nil
		}
		if slices.Contains(visiting, name) {
			return nil, &ConfigError{Message: fmt.Sprintf("extends goes in a circle: %s extends %s", visiting[len(visiting)-1], name)}
		}
		inherited := map[string]domain.Reference{}
		maps.Copy(inherited, base[name])
		if parent, ok := c.Extends[name]; ok {
			from, err := resolve(parent, append(visiting, name))
			if err != nil {
				return nil, err
			}
			maps.Copy(inherited, from)
		}
		c.parent[name] = inherited
		effective := maps.Clone(inherited)
		maps.Copy(effective, declared[name])
		c.shared[name] = effective
		return effective, nil
	}
	for name := range names {
		if _, err := resolve(name, nil); err != nil {
			return err
		}
	}
	c.Environments = environments{}
	for name, vars := range c.shared {
		c.Environments[name] = maps.Clone(vars)
	}
	if !root {
		return nil
	}
	local, err := loadLocal(filepath.Join(filepath.Dir(path), LocalFileName))
	if err != nil {
		return err
	}
	c.local = local
	for name, vars := range local {
		if c.Environments[name] == nil {
			return &ConfigError{Message: fmt.Sprintf("%s names %q, which is not an environment of envrune.yml", LocalFileName, name)}
		}
		maps.Copy(c.Environments[name], vars)
	}
	return nil
}

// loadLocal reads the personal override, which has one key, environments.
// A missing file is no override.
func loadLocal(path string) (environments, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var node yaml.Node
	if yaml.Unmarshal(raw, &node) != nil || len(node.Content) > 1 {
		return nil, &ConfigError{Message: LocalFileName + " is not valid YAML"}
	}
	if len(node.Content) == 0 {
		return nil, nil
	}
	pairs, err := mappingPairs(node.Content[0], LocalFileName)
	if err != nil {
		return nil, err
	}
	var out environments
	for _, pair := range pairs {
		if pair[0].Value != "environments" {
			return nil, configError(pair[0], "%s has one key, environments; %q is not it", LocalFileName, pair[0].Value)
		}
		if out, err = parseEnvironments(pair[1]); err != nil {
			return nil, fmt.Errorf("%s: %w", LocalFileName, err)
		}
	}
	return out, nil
}

// declared returns what the shared file itself should hold for the
// environments in c.Environments: without what each inherits, and without
// what came from the personal override.
func (c Config) declared() environments {
	out := environments{}
	for name, vars := range c.Environments {
		own := map[string]domain.Reference{}
		for variable, ref := range vars {
			if override, ok := c.local[name][variable]; ok && override == ref {
				// One person's choice: the shared file keeps what it had.
				shared, had := c.shared[name][variable]
				if !had {
					continue
				}
				ref = shared
			}
			if inherited, ok := c.parent[name][variable]; ok && inherited == ref {
				continue
			}
			own[variable] = ref
		}
		// An environment only the workspace root has stays there.
		if len(own) == 0 && c.shared != nil {
			if _, inherited := c.parent[name]; inherited && len(c.parent[name]) > 0 && !c.wrote(name) {
				continue
			}
		}
		out[name] = own
	}
	return out
}

// wrote reports whether the file itself named the environment: it did when
// the environment has a variable of its own or extends another.
func (c Config) wrote(name string) bool {
	if _, ok := c.Extends[name]; ok {
		return true
	}
	for variable, ref := range c.shared[name] {
		if inherited, ok := c.parent[name][variable]; !ok || inherited != ref {
			return true
		}
	}
	return false
}

// ownCloud is the cloud link this file itself declares.
func (c Config) ownCloud() string {
	if c.inheritedCloud {
		return ""
	}
	return c.Cloud
}

// SetLocalBinding maps variable to ref in one environment of the personal
// override next to the envrune.yml at path, creating the file if needed. It
// reports whether it created it, so the caller can keep it out of Git.
func SetLocalBinding(path, environment, variable string, ref domain.Reference) (created bool, err error) {
	if environment == "" || !variableName.MatchString(variable) {
		return false, ErrInvalidConfig
	}
	shared, err := Load(path)
	if err != nil {
		return false, err
	}
	if shared.Environments[environment] == nil {
		return false, &ConfigError{Message: fmt.Sprintf("%q is not an environment of envrune.yml", environment)}
	}
	local := filepath.Join(filepath.Dir(path), LocalFileName)
	lock, err := lockConfig(path)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	var doc yaml.Node
	raw, err := os.ReadFile(local)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		created = err != nil
		header := "One developer's own choices; not committed. See docs/project-file.md."
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: header,
			Content: []*yaml.Node{scalar("environments"), {Kind: yaml.MappingNode, Tag: "!!map"}}}}}
	} else {
		if _, err := loadLocal(local); err != nil {
			return false, err
		}
		if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) != 1 {
			return false, &ConfigError{Message: LocalFileName + " is not valid YAML"}
		}
	}
	root := doc.Content[0]
	envs := childValue(root, "environments")
	if envs == nil {
		envs = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, scalar("environments"), envs)
	}
	envs.Style = 0
	mapping := childValue(envs, environment)
	if mapping == nil {
		mapping = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		envs.Content = append(envs.Content, scalar(environment), mapping)
	}
	mapping.Style = 0
	if existing := childValue(mapping, variable); existing != nil {
		existing.Value, existing.Tag, existing.Style = ref.String(), "!!str", 0
	} else {
		mapping.Content = append(mapping.Content, scalar(variable), scalar(ref.String()))
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if encoder.Encode(&doc) != nil || encoder.Close() != nil {
		return false, ErrInvalidConfig
	}
	return created, writeFile(local, out.Bytes())
}
