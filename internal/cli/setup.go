package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

// setupAttempts is how many times setup asks again for a value that does
// not fit the variable before moving on.
const setupAttempts = 3

// setup walks a developer through every variable documented under
// variables: in envrune.yml, for one environment: it explains what each one
// is and how to get it, stores the value, and links it.
func (w Workspace) setup(argv []string) int {
	a, err := parseArgs(argv, []string{"env"}, nil, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError("setup [--env <environment>]")
	}
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	config, err := project.Load(projectPath)
	if err != nil {
		return w.fail(err, "The project configuration is invalid.")
	}
	status := w.status()
	if len(config.Variables) == 0 {
		status.Info("envrune.yml has no variables: section yet. Document each variable there, and `envrune setup` will guide the next developer through them. See docs/variables.md.")
		return 0
	}
	environment, err := app.ChooseEnvironment(config, a.options["env"])
	if err != nil {
		return w.fail(err, "Choose an environment with --env.")
	}
	if w.ReadChoice == nil || w.ReadSecret == nil {
		status.Error("envrune setup needs a terminal to ask for values.")
		return 1
	}
	status.Info(fmt.Sprintf("Setting up %d variables for %s.", len(config.Variables), environment))
	ready, missing := 0, []string{}
	for _, v := range config.Variables {
		ok, err := w.setupVariable(projectPath, config, environment, v)
		if err != nil {
			return w.fail(err, "Setup stopped.")
		}
		switch {
		case ok:
			ready++
		case v.Required:
			missing = append(missing, v.Name)
		}
	}
	if len(missing) > 0 {
		status.Warn(fmt.Sprintf("%d of %d variables are ready. Still missing: %s. Run `envrune setup` again when you have them.", ready, len(config.Variables), strings.Join(missing, ", ")))
		return 1
	}
	status.Success(fmt.Sprintf("%d of %d variables are ready for %s.", ready, len(config.Variables), environment))
	return 0
}

// setupVariable makes one variable ready and reports whether it is.
func (w Workspace) setupVariable(projectPath string, config project.Config, environment string, v project.Variable) (bool, error) {
	status := w.status()
	linked, isLinked := config.Environments[environment][v.Name]
	if isLinked {
		value, err := w.Session.Reveal(projectPath, linked.String())
		switch {
		case err == nil:
			reason := v.Check(value)
			wipe(value)
			if reason == "" {
				status.Success(fmt.Sprintf("%s is ready (%s).", v.Name, linked))
				return true, nil
			}
			status.Warn(fmt.Sprintf("%s (%s) %s.", v.Name, linked, reason))
		case !errors.Is(err, vault.ErrUnknownReference):
			return false, err
		}
	}

	fmt.Fprintf(w.Stdout, "\n%s\n", v.Name)
	if v.Description != "" {
		fmt.Fprintf(w.Stdout, "  %s\n", v.Description)
	}
	if v.HowToGet != "" {
		fmt.Fprintf(w.Stdout, "  How to get it: %s\n", v.HowToGet)
	}
	if expected := expectation(v); expected != "" {
		fmt.Fprintf(w.Stdout, "  Expected: %s\n", expected)
	}
	if !v.Required {
		choice, err := w.ReadChoice("Optional. Set it now? [y/N]")
		if err != nil || !acceptsSetup(choice) {
			return false, nil
		}
	}

	ref := linked
	if !isLinked {
		suggested := suggestReference(config.Project, v.Name, environment)
		for {
			answer, err := w.ReadChoice(fmt.Sprintf("Reference [%s]:", suggested))
			if err != nil {
				return false, err
			}
			if answer = strings.TrimSpace(answer); answer == "" {
				answer = suggested
			}
			if ref, err = domain.ParseReference(answer); err == nil {
				break
			}
			status.Error("Use lowercase words separated by dots, such as shop.database-url.")
		}
		// A value that is already stored can be linked as it is.
		if value, err := w.Session.Reveal(projectPath, ref.String()); err == nil {
			reason := v.Check(value)
			wipe(value)
			if reason == "" {
				choice, err := w.ReadChoice(fmt.Sprintf("%s is already stored. Use it? [Y/n]", ref))
				if err == nil && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(choice)), "n") {
					return true, w.linkForSetup(projectPath, environment, v.Name, ref)
				}
			}
		}
	}

	for attempt := 1; ; attempt++ {
		value, err := readConfirmedValue(w.ReadSecret, v.Name)
		if errors.Is(err, ErrValueConfirmation) || errors.Is(err, ErrEmptyValue) || errors.Is(err, ErrMultilineInput) {
			status.Error(describe(err, "The value was not accepted."))
			if attempt == setupAttempts {
				return false, nil
			}
			continue
		}
		if err != nil {
			return false, err
		}
		if reason := v.Check(value); reason != "" {
			wipe(value)
			status.Error(fmt.Sprintf("That value %s.", reason))
			if attempt == setupAttempts {
				return false, nil
			}
			continue
		}
		err = w.Session.Set(ref.String(), value)
		wipe(value)
		if err != nil {
			return false, err
		}
		break
	}
	if !isLinked {
		if err := w.linkForSetup(projectPath, environment, v.Name, ref); err != nil {
			return false, err
		}
	}
	status.Success(fmt.Sprintf("%s is ready (%s).", v.Name, ref))
	return true, nil
}

func (w Workspace) linkForSetup(projectPath, environment, variable string, ref domain.Reference) error {
	return w.Session.Link(projectPath, environment, variable, ref.String())
}

// expectation describes a valid value in words.
func expectation(v project.Variable) string {
	var parts []string
	switch v.Type {
	case "url":
		parts = append(parts, "a URL")
	case "int":
		parts = append(parts, "a whole number")
	case "bool":
		parts = append(parts, "true or false")
	}
	if v.Format != "" {
		parts = append(parts, "matching "+v.Format)
	}
	return strings.Join(parts, ", ")
}

// suggestReference proposes project.variable.environment, such as
// shop.database-url.development.
func suggestReference(projectName, variable, environment string) string {
	segments := []string{slug(projectName), slug(variable), slug(environment)}
	return strings.Join(segments, ".")
}

// slug turns text into a reference segment: lowercase letters, digits, and
// dashes, starting with a letter.
func slug(text string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(text) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == '_' || c == '-' || c == ' ' || c == '.':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" || out[0] < 'a' || out[0] > 'z' {
		out = "v" + out
	}
	return out
}
