package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"

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
}

// sources looks references up in the personal vault and, for references that
// start with "team.", in the team file next to envrune.yml.
type sources struct {
	vault    *vault.Opened // nil in identity-only mode
	identity func() (string, error)
	team     *team.File
	teamErr  error
	loaded   bool
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

func (s *sources) value(projectPath string, ref domain.Reference) ([]byte, bool, error) {
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

func (s *sources) close() {
	if s.team != nil {
		s.team.Close()
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
		value, exists, err := src.value(projectPath, mappings[variable])
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
	return Resolved{Environment: environment, Pairs: pairs}, nil
}
