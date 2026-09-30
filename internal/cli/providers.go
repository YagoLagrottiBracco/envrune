package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/provider"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

// providerOptions parses `<provider> [--env e] [provider flags]` and fills
// in the project folder for providers that look for their own link file.
func (w Workspace) providerOptions(argv []string, pull bool) (provider.Provider, provider.Options, string, project.Config, int) {
	names := strings.Join(provider.Names(pull), "|")
	verb := "push"
	if pull {
		verb = "pull"
	}
	usage := fmt.Sprintf("%s <%s> [--env <environment>] [provider options]", verb, names)
	if len(argv) == 0 {
		return nil, nil, "", project.Config{}, w.usageError(usage)
	}
	p, ok := provider.Get(argv[0])
	if !ok {
		return nil, nil, "", project.Config{}, w.usageError(usage)
	}
	if _, can := p.(provider.Puller); pull && !can {
		w.status().Error(fmt.Sprintf("%s only receives values; they cannot be read back. Providers that can pull: %s.", p.Name(), strings.Join(provider.Names(true), ", ")))
		return nil, nil, "", project.Config{}, 2
	}
	if _, can := p.(provider.Pusher); !pull && !can {
		w.status().Error(fmt.Sprintf("EnvRune cannot push to %s. Providers that can: %s.", p.Name(), strings.Join(provider.Names(false), ", ")))
		return nil, nil, "", project.Config{}, 2
	}
	a, err := parseArgs(argv[1:], append([]string{"env"}, p.Flags()...), nil, false)
	if err != nil || len(a.positional) != 0 {
		flags := make([]string, len(p.Flags()))
		for i, f := range p.Flags() {
			flags[i] = "[--" + f + " …]"
		}
		return nil, nil, "", project.Config{}, w.usageError(fmt.Sprintf("%s %s [--env <environment>] %s", verb, p.Name(), strings.Join(flags, " ")))
	}
	projectPath, err := w.findProject()
	if err != nil {
		return nil, nil, "", project.Config{}, w.fail(err, "No Envrune project configuration was found.")
	}
	config, err := project.Load(projectPath)
	if err != nil {
		return nil, nil, "", project.Config{}, w.fail(err, "The project configuration is invalid.")
	}
	opts := provider.Options{}
	for key, value := range a.options {
		if key != "env" {
			opts[key] = value
		}
	}
	if opts["dir"] == "" {
		opts["dir"] = filepath.Dir(projectPath)
	}
	environment, err := app.ChooseEnvironment(config, a.options["env"])
	if err != nil {
		return nil, nil, "", project.Config{}, w.fail(err, "Choose an environment with --env.")
	}
	return p, opts, environment, config, -1
}

// pull copies values from a service into the vault and links them in
// envrune.yml, after showing what would change, without values.
func (w Workspace) pull(argv []string) int {
	p, opts, environment, config, code := w.providerOptions(argv, true)
	if code >= 0 {
		return code
	}
	projectPath, _ := w.findProject()
	status := w.status()
	values, notes, err := p.(provider.Puller).Pull(context.Background(), environment, opts)
	defer func() {
		for _, v := range values {
			wipe(v.Value)
		}
	}()
	if err != nil {
		status.Error(sentence(err.Error()))
		return 1
	}
	type change struct {
		value  provider.Value
		ref    domain.Reference
		state  string
		linked bool
	}
	var changes []change
	pending := 0
	for _, v := range values {
		if !project.VariableName(v.Name) {
			notes = append(notes, v.Name+" is not a valid variable name")
			continue
		}
		ref, linked := config.Environments[environment][v.Name]
		if !linked {
			ref = domain.Reference(suggestReference(config.Project, v.Name, environment))
		}
		if team.IsTeamReference(ref) {
			notes = append(notes, fmt.Sprintf("%s is linked to the team reference %s; update it with `envrune team set %s`", v.Name, ref, ref))
			continue
		}
		state := "new"
		current, err := w.Session.Reveal(projectPath, ref.String())
		switch {
		case err == nil:
			state = "changed"
			if bytes.Equal(current, v.Value) {
				state = "unchanged"
			}
			wipe(current)
		case !errors.Is(err, vault.ErrUnknownReference):
			return w.fail(err, "The vault could not be read.")
		}
		if state != "unchanged" || !linked {
			pending++
		}
		changes = append(changes, change{v, ref, state, linked})
	}
	fmt.Fprintf(w.Stdout, "From %s into %s (values are not shown):\n", p.Target(environment, opts), environment)
	for _, c := range changes {
		link := ""
		if !c.linked {
			link = ", will be linked"
		}
		fmt.Fprintf(w.Stdout, "  %-28s → %s (%s%s)\n", c.value.Name, c.ref, c.state, link)
	}
	for _, note := range notes {
		status.Warn(strings.TrimSuffix(note, ".") + ".") // notes may start with a variable name
	}
	if pending == 0 {
		status.Success("The vault already matches.")
		return 0
	}
	if w.ReadChoice == nil {
		status.Error("envrune pull needs a terminal to confirm.")
		return 1
	}
	choice, err := w.ReadChoice(fmt.Sprintf("Store %d %s in the vault? [y/N]", pending, plural(pending, "value", "values")))
	if err != nil || !acceptsSetup(choice) {
		status.Info("Nothing was changed.")
		return 0
	}
	for _, c := range changes {
		if c.state != "unchanged" {
			if err := w.Session.Set(c.ref.String(), c.value.Value); err != nil {
				return w.fail(err, "Could not store "+c.ref.String()+".")
			}
		}
		if !c.linked {
			if err := w.Session.Link(projectPath, environment, c.value.Name, c.ref.String()); err != nil {
				return w.fail(err, "Could not link "+c.value.Name+".")
			}
		}
	}
	status.Success(fmt.Sprintf("Pulled %d %s into %s. Earlier values stay in `envrune history`.", pending, plural(pending, "value", "values"), environment))
	return 0
}

// push sends the variables of an environment to a service, after the user
// types YES.
func (w Workspace) push(argv []string) int {
	p, opts, environment, _, code := w.providerOptions(argv, false)
	if code >= 0 {
		return code
	}
	_, resolved, err := w.resolve(environment)
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	for _, pair := range resolved.Pairs {
		fmt.Fprintln(w.Stdout, pair.Name)
	}
	w.status().Warn(fmt.Sprintf("These %d variables from %s will be stored in %s.", len(resolved.Pairs), resolved.Environment, p.Target(resolved.Environment, opts)))
	if !w.confirm() {
		w.status().Error("Confirmation is required.")
		return 1
	}
	values := make([]provider.Value, len(resolved.Pairs))
	for i, pair := range resolved.Pairs {
		values[i] = provider.Value{Name: pair.Name, Value: pair.Value}
	}
	if err := p.(provider.Pusher).Push(context.Background(), resolved.Environment, values, opts); err != nil {
		w.status().Error(sentence(err.Error()))
		return 1
	}
	w.status().Success(fmt.Sprintf("Stored %d %s in %s.", len(values), plural(len(values), "variable", "variables"), p.Target(resolved.Environment, opts)))
	return 0
}
