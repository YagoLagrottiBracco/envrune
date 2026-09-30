package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/runner"
	"github.com/envrune/envrune/internal/vault"
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
	return fmt.Sprintf("secret %s not exist in the vault: %s", noun, strings.Join(parts, ", "))
}

func (e *MissingSecretError) Is(target error) bool { return target == ErrMissingSecret }

func resolveEnvironment(v *vault.Opened, projectPath, environment string) ([]runner.Pair, error) {
	config, err := project.Load(projectPath)
	if err != nil {
		return nil, err
	}
	mappings, ok := config.Environments[environment]
	if !ok {
		available := make([]string, 0, len(config.Environments))
		for name := range config.Environments {
			available = append(available, name)
		}
		sort.Strings(available)
		return nil, &MissingEnvironmentError{Environment: environment, Available: available}
	}
	variables := make([]string, 0, len(mappings))
	for variable := range mappings {
		variables = append(variables, variable)
	}
	sort.Strings(variables)
	pairs := make([]runner.Pair, 0, len(variables))
	var missing []MissingBinding
	for _, variable := range variables {
		value, exists := v.Value(mappings[variable])
		if !exists {
			missing = append(missing, MissingBinding{Variable: variable, Reference: mappings[variable]})
			continue
		}
		pairs = append(pairs, runner.Pair{Name: variable, Value: value})
	}
	if len(missing) > 0 {
		wipePairs(pairs)
		return nil, &MissingSecretError{Environment: environment, Missing: missing}
	}
	return pairs, nil
}
