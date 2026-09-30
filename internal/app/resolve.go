package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

var ErrMissingEnvironment = errors.New("environment configuration not found")
var ErrMissingSecret = errors.New("configured secret is unavailable")

// MissingEnvironmentError names the requested environment and the ones the
// project defines. Names are metadata, never secret values.
type MissingEnvironmentError struct {
	Environment string
	Available   []string
}

func (e *MissingEnvironmentError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("environment %q does not exist; envrune.yml defines no environments yet", e.Environment)
	}
	return fmt.Sprintf("environment %q does not exist; available: %s", e.Environment, strings.Join(e.Available, ", "))
}

func (e *MissingEnvironmentError) Is(target error) bool { return target == ErrMissingEnvironment }

// NoEnvironmentChosenError means no --env was given and envrune.yml has no
// default_env while it defines several environments.
type NoEnvironmentChosenError struct{ Available []string }

func (e *NoEnvironmentChosenError) Error() string {
	if len(e.Available) == 0 {
		return "envrune.yml defines no environments yet; pass --env to create one"
	}
	return fmt.Sprintf("choose an environment with --env or set default_env in envrune.yml; available: %s", strings.Join(e.Available, ", "))
}

func (e *NoEnvironmentChosenError) Is(target error) bool { return target == ErrMissingEnvironment }

// ChooseEnvironment picks the requested environment, else default_env, else
// the only environment.
func ChooseEnvironment(config project.Config, requested string) (string, error) {
	names := config.EnvironmentNames()
	switch {
	case requested != "":
		if config.Environments[requested] == nil {
			return "", &MissingEnvironmentError{Environment: requested, Available: names}
		}
		return requested, nil
	case config.DefaultEnv != "":
		if config.Environments[config.DefaultEnv] == nil {
			return "", &MissingEnvironmentError{Environment: config.DefaultEnv, Available: names}
		}
		return config.DefaultEnv, nil
	case len(names) == 1:
		return names[0], nil
	}
	return "", &NoEnvironmentChosenError{Available: names}
}

// MissingBinding is one variable whose reference has no stored secret.
type MissingBinding struct {
	Variable  string
	Reference domain.Reference
}

type MissingSecretError struct {
	Environment string
	Missing     []MissingBinding
}

func (e *MissingSecretError) Error() string {
	parts := make([]string, len(e.Missing))
	for i, m := range e.Missing {
		parts[i] = fmt.Sprintf("%s (used by %s)", m.Reference, m.Variable)
	}
	noun := "reference does"
	if len(parts) > 1 {
		noun = "references do"
	}
	return fmt.Sprintf("secret %s not exist: %s", noun, strings.Join(parts, ", "))
}

func (e *MissingSecretError) Is(target error) bool { return target == ErrMissingSecret }

// Resolved is one environment ready to inject.
type Resolved struct {
	Environment string
	Pairs       []runner.Pair
	// Restricted is set when a value came from a cloud environment where
	// this user is a consumer: it may reach a process, never the screen,
	// a file, or the clipboard (docs/cloud-crypto.md, Roles).
	Restricted bool
}

// ErrConsumerValue means a command would show a value this user may only
// use, as a consumer of its cloud environment.
var ErrConsumerValue = errors.New("your role in the cloud environment (consumer) lets programs use this value, not show, copy, or export it")

// CloudSource returns the verified values of one cloud environment and this
// user's role in it; the role is empty for a machine token.
type CloudSource func(path cloud.Path) (map[string][]byte, string, error)

// CloudError is a cloud reference that could not be resolved. Its message
// names organizations, environments, and secrets, never a value.
type CloudError struct{ Err error }

func (e *CloudError) Error() string { return e.Err.Error() }
func (e *CloudError) Unwrap() error { return e.Err }

type cloudEnv struct {
	values map[string][]byte
	role   string
}

// sources looks references up in the personal vault, in the team file next
// to envrune.yml for references that start with "team.", and in EnvRune
// Cloud for references that start with "cloud." when envrune.yml links a
// cloud project.
type sources struct {
	vault    *vault.Opened // nil in identity-only mode
	identity func() (string, error)
	team     *team.File
	teamErr  error
	loaded   bool

	cloud      CloudSource // nil without a cloud source
	cloudEnvs  map[string]*cloudEnv
	links      map[string]string // project path → cloud link, "" for none
	restricted bool
}

func (s *sources) teamFile(projectPath string) (*team.File, error) {
	if !s.loaded {
		s.loaded = true
		path := team.Path(projectPath)
		if !team.Exists(path) {
			s.teamErr = ErrNoTeamFile
		} else if identity, err := s.identity(); err != nil {
			s.teamErr = err
		} else {
			s.team, s.teamErr = team.Open(path, identity)
		}
	}
	return s.team, s.teamErr
}

// cloudLink returns the cloud project envrune.yml links, or "".
func (s *sources) cloudLink(projectPath string) string {
	if s.links == nil {
		s.links = map[string]string{}
	}
	link, ok := s.links[projectPath]
	if !ok {
		if config, err := project.Load(projectPath); err == nil {
			link = config.Cloud
		}
		s.links[projectPath] = link
	}
	return link
}

// value finds one reference. environment names the envrune.yml environment
// being resolved, which cloud.<name> references need; it may be empty.
func (s *sources) value(projectPath, environment string, ref domain.Reference) ([]byte, bool, error) {
	if link := s.cloudLink(projectPath); link != "" {
		if path, ok, err := cloud.ReferencePath(ref.String(), link, environment); ok {
			if err != nil {
				return nil, false, &CloudError{Err: err}
			}
			return s.cloudValue(path)
		}
	}
	if team.IsTeamReference(ref) {
		file, err := s.teamFile(projectPath)
		if err != nil {
			return nil, false, err
		}
		value, ok := file.Value(ref)
		return value, ok, nil
	}
	if s.vault == nil {
		return nil, false, ErrNoVault
	}
	value, ok := s.vault.Value(ref)
	return value, ok, nil
}

func (s *sources) cloudValue(path cloud.Path) ([]byte, bool, error) {
	if s.cloud == nil {
		return nil, false, ErrNoCloud
	}
	env := path
	env.Name = ""
	if s.cloudEnvs == nil {
		s.cloudEnvs = map[string]*cloudEnv{}
	}
	entry := s.cloudEnvs[env.String()]
	if entry == nil {
		values, role, err := s.cloud(env)
		if err != nil {
			return nil, false, &CloudError{Err: err}
		}
		entry = &cloudEnv{values: values, role: role}
		s.cloudEnvs[env.String()] = entry
	}
	value, ok := entry.values[path.Name]
	if !ok {
		return nil, false, nil
	}
	if entry.role == cloudcrypto.RoleConsumer {
		s.restricted = true
	}
	return append([]byte(nil), value...), true, nil
}

func (s *sources) close() {
	if s.team != nil {
		s.team.Close()
	}
	for _, entry := range s.cloudEnvs {
		for _, v := range entry.values {
			wipe(v)
		}
	}
}

func resolve(src *sources, projectPath, requested string) (Resolved, error) {
	config, err := project.Load(projectPath)
	if err != nil {
		return Resolved{}, err
	}
	environment, err := ChooseEnvironment(config, requested)
	if err != nil {
		return Resolved{}, err
	}
	mappings := config.Environments[environment]
	variables := make([]string, 0, len(mappings))
	for variable := range mappings {
		variables = append(variables, variable)
	}
	sort.Strings(variables)
	pairs := make([]runner.Pair, 0, len(variables))
	var missing []MissingBinding
	for _, variable := range variables {
		value, exists, err := src.value(projectPath, environment, mappings[variable])
		if err != nil {
			wipePairs(pairs)
			return Resolved{}, err
		}
		if !exists {
			missing = append(missing, MissingBinding{Variable: variable, Reference: mappings[variable]})
			continue
		}
		pairs = append(pairs, runner.Pair{Name: variable, Value: value})
	}
	if len(missing) > 0 {
		wipePairs(pairs)
		return Resolved{}, &MissingSecretError{Environment: environment, Missing: missing}
	}
	if problems := checkVariables(config, environment, pairs); len(problems) > 0 {
		wipePairs(pairs)
		return Resolved{}, &InvalidVariablesError{Environment: environment, Problems: problems}
	}
	return Resolved{Environment: environment, Pairs: pairs, Restricted: src.restricted}, nil
}

// VariableProblem is a variable whose value does not fit what variables:
// in envrune.yml says about it. Reason never contains the value.
type VariableProblem struct {
	Variable  string
	Reference domain.Reference // empty when the variable is not linked
	Reason    string
}

// InvalidVariablesError means values failed the checks of variables:, so
// the command did not start.
type InvalidVariablesError struct {
	Environment string
	Problems    []VariableProblem
}

func (e *InvalidVariablesError) Error() string {
	parts := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		if p.Reference == "" {
			parts[i] = fmt.Sprintf("%s %s", p.Variable, p.Reason)
		} else {
			parts[i] = fmt.Sprintf("%s (%s) %s", p.Variable, p.Reference, p.Reason)
		}
	}
	return fmt.Sprintf("environment %q: %s", e.Environment, strings.Join(parts, "; "))
}

func checkVariables(config project.Config, environment string, pairs []runner.Pair) []VariableProblem {
	mappings := config.Environments[environment]
	var problems []VariableProblem
	for _, v := range config.Variables {
		ref, linked := mappings[v.Name]
		if !linked {
			if v.Required {
				problems = append(problems, VariableProblem{Variable: v.Name, Reason: "is required but not linked in " + environment})
			}
			continue
		}
		for _, pair := range pairs {
			if pair.Name == v.Name {
				if reason := v.Check(pair.Value); reason != "" {
					problems = append(problems, VariableProblem{Variable: v.Name, Reference: ref, Reason: reason})
				}
			}
		}
	}
	return problems
}

// CloudPath reports whether ref, used in environment of a project with
// config, is a cloud reference, and which secret it names.
func CloudPath(config project.Config, environment string, ref domain.Reference) (cloud.Path, bool, error) {
	if config.Cloud == "" {
		return cloud.Path{}, false, nil
	}
	return cloud.ReferencePath(ref.String(), config.Cloud, environment)
}
