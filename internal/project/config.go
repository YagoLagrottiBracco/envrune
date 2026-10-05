// Package project owns safe, versionable Envrune project configuration.
package project

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"gopkg.in/yaml.v3"
)

var ErrInvalidConfig = errors.New("invalid project configuration")
var ErrProjectBusy = errors.New("project configuration is busy")
var variableName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
var commandName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
var driveLetter = regexp.MustCompile(`^[A-Za-z]:`)

// cloudLink is an EnvRune Cloud organization and project, such as acme/shop.
var cloudLink = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}/[a-z][a-z0-9-]{0,62}$`)

func VariableName(value string) bool { return variableName.MatchString(value) }

// CommandName reports whether value can name a command in envrune.yml.
func CommandName(value string) bool { return commandName.MatchString(value) }

// ConfigError says where envrune.yml is wrong. It never carries values from
// the file other than key names.
type ConfigError struct {
	Line    int
	Message string
}

func (e *ConfigError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("envrune.yml line %d: %s", e.Line, e.Message)
	}
	return "envrune.yml: " + e.Message
}

func (e *ConfigError) Is(target error) bool { return target == ErrInvalidConfig }

func configError(node *yaml.Node, format string, args ...any) error {
	line := 0
	if node != nil {
		line = node.Line
	}
	return &ConfigError{Line: line, Message: fmt.Sprintf(format, args...)}
}

// Command is a named command from envrune.yml, run with `envrune <name>`.
type Command struct {
	Run string // parsed like a shell line, but never run by a shell
	Dir string // relative to envrune.yml; empty means the project root
	Env string // environment; empty means the default environment
	// Project is a folder, relative to envrune.yml, whose own envrune.yml
	// supplies the command's secrets and default environment. It lets one
	// `envrune up` start services that each keep their own envrune.yml.
	Project string
}

// Target returns the envrune.yml that supplies the command's secrets and the
// folder the command runs in, given the envrune.yml that defines it.
func (c Command) Target(configPath string) (secrets, dir string) {
	root := filepath.Dir(configPath)
	secrets, dir = configPath, filepath.Join(root, c.Dir)
	if c.Project != "" {
		secrets = filepath.Join(root, c.Project, filepath.Base(configPath))
		if c.Dir == "" {
			dir = filepath.Join(root, c.Project)
		}
	}
	return secrets, dir
}

type Config struct {
	Version    int
	Project    string
	DefaultEnv string
	// Cloud links an EnvRune Cloud project, "org/project"; only then do
	// references that start with "cloud." resolve from the cloud.
	Cloud        string
	Commands     map[string]Command
	Up           []string
	Variables    []Variable // in the order envrune.yml lists them
	// Environments is what each environment resolves: its own variables on
	// top of the ones it inherits and under the user's personal override
	// (docs/project-file.md).
	Environments map[string]map[string]domain.Reference
	// Extends maps an environment to the one it builds on.
	Extends map[string]string
	// Workspace is the folder, relative to this file, of the envrune.yml
	// whose environments this one starts from.
	Workspace string
	// Files lists the variables that receive the path of a file holding the
	// secret, instead of its value.
	Files []string
	// Render maps a variable to a template, relative to this file; the
	// variable receives the path of the template filled in.
	Render map[string]string
	// Checks are commands that succeed while a secret still works.
	Checks map[string]string
	// Forward maps a variable to the https address of a service. The
	// variable receives that address, or a local one that stands for it
	// when a sensitive secret is used there, for programs that cannot be
	// pointed at a proxy.
	Forward map[string]string

	// shared is Environments without the personal override, and local the
	// override, so the shared file can be written back without either what
	// it inherits or what is one person's.
	shared map[string]map[string]domain.Reference
	local  map[string]map[string]domain.Reference
	parent map[string]map[string]domain.Reference // what each environment inherits
	// inheritedCloud says Cloud is the workspace root's, not this file's.
	inheritedCloud bool
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, ErrInvalidConfig
	}
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return Config{}, &ConfigError{Message: "not valid YAML"}
	}
	if len(node.Content) != 1 {
		return Config{}, &ConfigError{Message: "expected one YAML document"}
	}
	config, err := parseDocument(node.Content[0])
	if err != nil {
		return Config{}, err
	}
	if err := config.layer(path, true); err != nil {
		return Config{}, err
	}
	return config, nil
}

func mappingPairs(node *yaml.Node, what string) ([][2]*yaml.Node, error) {
	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return nil, configError(node, "%s must be a mapping", what)
	}
	seen := map[string]bool{}
	pairs := make([][2]*yaml.Node, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "" {
			return nil, configError(k, "%s has an invalid key", what)
		}
		if seen[k.Value] {
			return nil, configError(k, "%s has a duplicate key %q", what, k.Value)
		}
		seen[k.Value] = true
		pairs = append(pairs, [2]*yaml.Node{k, v})
	}
	return pairs, nil
}

func stringValue(node *yaml.Node, what string) (string, error) {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" || node.Value == "" {
		return "", configError(node, "%s must be a non-empty string", what)
	}
	return node.Value, nil
}

func parseDocument(root *yaml.Node) (Config, error) {
	pairs, err := mappingPairs(root, "the document")
	if err != nil {
		return Config{}, err
	}
	out := Config{Version: 1, Commands: map[string]Command{}, Environments: map[string]map[string]domain.Reference{}}
	var seenVersion, seenProject, seenEnvironments bool
	for _, pair := range pairs {
		k, v := pair[0], pair[1]
		switch k.Value {
		case "version":
			if v.Kind != yaml.ScalarNode || v.Tag != "!!int" || v.Value != "1" {
				return Config{}, configError(v, "version must be 1")
			}
			seenVersion = true
		case "project":
			if out.Project, err = stringValue(v, "project"); err != nil {
				return Config{}, err
			}
			seenProject = true
		case "default_env":
			if out.DefaultEnv, err = stringValue(v, "default_env"); err != nil {
				return Config{}, err
			}
		case "cloud":
			if out.Cloud, err = stringValue(v, "cloud"); err != nil {
				return Config{}, err
			}
			if !cloudLink.MatchString(out.Cloud) {
				return Config{}, configError(v, "cloud must name an organization and project, such as acme/shop")
			}
		case "commands":
			if out.Commands, err = parseCommands(v); err != nil {
				return Config{}, err
			}
		case "up":
			if out.Up, err = parseUp(v); err != nil {
				return Config{}, err
			}
		case "variables":
			if out.Variables, err = parseVariables(v); err != nil {
				return Config{}, err
			}
		case "environments":
			if out.Environments, err = parseEnvironments(v); err != nil {
				return Config{}, err
			}
			seenEnvironments = true
		case "extends":
			if out.Extends, err = parseStrings(v, "extends"); err != nil {
				return Config{}, err
			}
		case "workspace":
			if out.Workspace, err = stringValue(v, "workspace"); err != nil {
				return Config{}, err
			}
			if strings.HasPrefix(out.Workspace, "/") || strings.HasPrefix(out.Workspace, `\`) || driveLetter.MatchString(out.Workspace) {
				return Config{}, configError(v, "workspace must be a folder relative to envrune.yml, such as ..")
			}
		case "files":
			if out.Files, err = parseVariableList(v, "files"); err != nil {
				return Config{}, err
			}
		case "render":
			if out.Render, err = parseStrings(v, "render"); err != nil {
				return Config{}, err
			}
			for name := range out.Render {
				if !variableName.MatchString(name) {
					return Config{}, configError(v, "render: %q is not a valid variable name; use names like APP_CONFIG", name)
				}
			}
		case "checks":
			if out.Checks, err = parseStrings(v, "checks"); err != nil {
				return Config{}, err
			}
			for name := range out.Checks {
				if !commandName.MatchString(name) {
					return Config{}, configError(v, "checks: %q is not a valid name; use lowercase letters, digits, - and _", name)
				}
			}
		case "forward":
			if out.Forward, err = parseStrings(v, "forward"); err != nil {
				return Config{}, err
			}
			for name, address := range out.Forward {
				if !variableName.MatchString(name) {
					return Config{}, configError(v, "forward: %q is not a valid variable name; use names like PAYMENTS_URL", name)
				}
				if _, err := ForwardTarget(address); err != nil {
					return Config{}, configError(v, "forward.%s: %v", name, err)
				}
			}
		default:
			return Config{}, configError(k, "unknown key %q", k.Value)
		}
	}
	if !seenVersion || !seenProject || !seenEnvironments {
		return Config{}, configError(root, "version, project, and environments are required")
	}
	for name := range out.Forward {
		for environment, bindings := range out.Environments {
			if _, bound := bindings[name]; bound {
				return Config{}, configError(root, "%s is in forward and in the %s environment; a variable is one or the other", name, environment)
			}
		}
	}
	return out, nil
}

func parseEnvironments(node *yaml.Node) (map[string]map[string]domain.Reference, error) {
	pairs, err := mappingPairs(node, "environments")
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]domain.Reference{}
	for _, pair := range pairs {
		environment, mapping := pair[0].Value, pair[1]
		vars, err := mappingPairs(mapping, "environment "+environment)
		if err != nil {
			return nil, err
		}
		refs := map[string]domain.Reference{}
		for _, v := range vars {
			if !variableName.MatchString(v[0].Value) {
				return nil, configError(v[0], "%q is not a valid variable name; use names like API_KEY", v[0].Value)
			}
			if v[1].Kind != yaml.ScalarNode || v[1].Tag != "!!str" {
				return nil, configError(v[1], "%s must map to a secret reference", v[0].Value)
			}
			ref, err := domain.ParseReference(v[1].Value)
			if err != nil {
				// The value is not echoed: it may be a secret pasted by mistake.
				return nil, configError(v[1], "%s must map to a secret reference such as openai.personal, not a value", v[0].Value)
			}
			refs[v[0].Value] = ref
		}
		out[environment] = refs
	}
	return out, nil
}

func parseCommands(node *yaml.Node) (map[string]Command, error) {
	pairs, err := mappingPairs(node, "commands")
	if err != nil {
		return nil, err
	}
	out := map[string]Command{}
	for _, pair := range pairs {
		name, value := pair[0].Value, pair[1]
		if !commandName.MatchString(name) {
			return nil, configError(pair[0], "%q is not a valid command name; use lowercase letters, digits, - and _", name)
		}
		if value.Kind == yaml.ScalarNode {
			run, err := stringValue(value, "commands."+name)
			if err != nil {
				return nil, err
			}
			out[name] = Command{Run: run}
			continue
		}
		fields, err := mappingPairs(value, "commands."+name)
		if err != nil {
			return nil, configError(value, "commands.%s must be a command string or a mapping with run, dir, env, and project", name)
		}
		var command Command
		for _, field := range fields {
			text, err := stringValue(field[1], "commands."+name+"."+field[0].Value)
			if err != nil {
				return nil, err
			}
			switch field[0].Value {
			case "run":
				command.Run = text
			case "dir":
				command.Dir = text
			case "env":
				command.Env = text
			case "project":
				// Checked the same way on every system, so the file stays portable.
				if text == "" || strings.HasPrefix(text, "/") || strings.HasPrefix(text, `\`) || driveLetter.MatchString(text) {
					return nil, configError(field[1], "commands.%s.project must be a folder relative to envrune.yml", name)
				}
				command.Project = text
			default:
				return nil, configError(field[0], "commands.%s has unknown key %q", name, field[0].Value)
			}
		}
		if command.Run == "" {
			return nil, configError(value, "commands.%s needs a run key", name)
		}
		out[name] = command
	}
	return out, nil
}

func parseUp(node *yaml.Node) ([]string, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, configError(node, "up must be a list of command names")
	}
	var out []string
	for _, item := range node.Content {
		name, err := stringValue(item, "up")
		if err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}

// Validate checks references between sections, such as default_env naming
// an environment that exists.
func (c Config) Validate() []string {
	var problems []string
	if c.DefaultEnv != "" && c.Environments[c.DefaultEnv] == nil {
		problems = append(problems, fmt.Sprintf("default_env %q is not an environment", c.DefaultEnv))
	}
	names := make([]string, 0, len(c.Commands))
	for name := range c.Commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// A command with project: uses the environments of that envrune.yml.
		if command := c.Commands[name]; command.Project == "" && command.Env != "" && c.Environments[command.Env] == nil {
			problems = append(problems, fmt.Sprintf("commands.%s uses environment %q, which does not exist", name, command.Env))
		}
	}
	for _, name := range c.Up {
		if _, ok := c.Commands[name]; !ok {
			problems = append(problems, fmt.Sprintf("up lists %q, which is not in commands", name))
		}
	}
	return problems
}

// EnvironmentNames returns the environment names in sorted order.
func (c Config) EnvironmentNames() []string {
	names := make([]string, 0, len(c.Environments))
	for name := range c.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func WriteAtomic(path string, config Config) error {
	if config.Version != 1 || config.Project == "" || config.Environments == nil {
		return ErrInvalidConfig
	}
	for environment, mappings := range config.Environments {
		if environment == "" {
			return ErrInvalidConfig
		}
		for variable, ref := range mappings {
			if !variableName.MatchString(variable) {
				return ErrInvalidConfig
			}
			if _, err := domain.ParseReference(ref.String()); err != nil {
				return ErrInvalidConfig
			}
		}
	}
	type commandYAML struct {
		Run     string `yaml:"run"`
		Dir     string `yaml:"dir,omitempty"`
		Env     string `yaml:"env,omitempty"`
		Project string `yaml:"project,omitempty"`
	}
	commands := map[string]any{}
	for name, command := range config.Commands {
		if command.Dir == "" && command.Env == "" && command.Project == "" {
			commands[name] = command.Run
		} else {
			commands[name] = commandYAML{command.Run, command.Dir, command.Env, command.Project}
		}
	}
	raw, err := yaml.Marshal(struct {
		Version      int                                    `yaml:"version"`
		Project      string                                 `yaml:"project"`
		DefaultEnv   string                                 `yaml:"default_env,omitempty"`
		Cloud        string                                 `yaml:"cloud,omitempty"`
		Workspace    string                                 `yaml:"workspace,omitempty"`
		Commands     map[string]any                         `yaml:"commands,omitempty"`
		Up           []string                               `yaml:"up,omitempty"`
		Environments map[string]map[string]domain.Reference `yaml:"environments"`
		Extends      map[string]string                      `yaml:"extends,omitempty"`
		Files        []string                               `yaml:"files,omitempty"`
		Render       map[string]string                      `yaml:"render,omitempty"`
		Checks       map[string]string                      `yaml:"checks,omitempty"`
		Forward      map[string]string                      `yaml:"forward,omitempty"`
	}{1, config.Project, config.DefaultEnv, config.ownCloud(), config.Workspace, commands, config.Up, config.declared(),
		config.Extends, config.Files, config.Render, config.Checks, config.Forward})
	if err != nil {
		return ErrInvalidConfig
	}
	return writeFile(path, raw)
}

func writeFile(path string, raw []byte) error {
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
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
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

// SetBinding maps variable to ref in one environment. It edits the YAML tree
// in place, so comments, key order, and the other sections are kept.
func SetBinding(path, environment, variable string, ref domain.Reference) error {
	if environment == "" || !variableName.MatchString(variable) {
		return ErrInvalidConfig
	}
	lock, err := lockConfig(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		return ErrInvalidConfig
	}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) != 1 {
		return &ConfigError{Message: "not valid YAML"}
	}
	if _, err := parseDocument(doc.Content[0]); err != nil {
		return err
	}
	environments := childValue(doc.Content[0], "environments")
	if environments.Style&yaml.FlowStyle != 0 {
		environments.Style = 0 // turn `environments: {}` into a block mapping
	}
	mapping := childValue(environments, environment)
	if mapping == nil {
		mapping = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		environments.Content = append(environments.Content, scalar(environment), mapping)
	}
	if mapping.Style&yaml.FlowStyle != 0 {
		mapping.Style = 0
	}
	if existing := childValue(mapping, variable); existing != nil {
		existing.Value, existing.Tag, existing.Style = ref.String(), "!!str", 0
	} else {
		mapping.Content = append(mapping.Content, scalar(variable), scalar(ref.String()))
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if encoder.Encode(&doc) != nil || encoder.Close() != nil {
		return ErrInvalidConfig
	}
	return writeFile(path, out.Bytes())
}

func childValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// UpdateAtomic rewrites the whole file from a Config. Prefer SetBinding,
// which keeps comments.
func UpdateAtomic(path string, update func(*Config) error) error {
	lock, err := lockConfig(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	config, err := Load(path)
	if err != nil {
		return err
	}
	if err := update(&config); err != nil {
		return err
	}
	return WriteAtomic(path, config)
}
