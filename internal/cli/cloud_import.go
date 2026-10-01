package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
)

const cloudImportUsage = "cloud import-team <org/project/env> [--relink] [--yes]"

// cloudNames gives each team reference its name in the cloud: cloud names
// are lowercase letters, digits, and dashes, so team.stripe.key becomes
// stripe-key. It refuses a name that cannot be made valid, and two
// references that would become the same name.
func cloudNames(refs []string) (map[string]string, error) {
	names, taken := map[string]string{}, map[string]string{}
	for _, ref := range refs {
		name := strings.Map(func(r rune) rune {
			if r == '_' || r == '.' || r == '@' {
				return '-'
			}
			return r
		}, strings.ToLower(strings.TrimPrefix(ref, team.Prefix)))
		if _, err := cloud.ParsePath("o/p/e/"+name, true); err != nil {
			return nil, fmt.Errorf("%s has no valid name in the cloud (%q): rename it with `envrune team` first", ref, name)
		}
		if other, ok := taken[name]; ok {
			return nil, fmt.Errorf("%s and %s would both be %q in the cloud: rename one first", other, ref, name)
		}
		names[ref], taken[name] = name, ref
	}
	return names, nil
}

// relinkTeam points the variables of envrune.yml that read imported team
// references at the cloud secrets instead, linking the file to the cloud
// project if it is not linked. It returns the variables it changed and the
// ones it could not, as "environment VARIABLE".
func relinkTeam(projectPath string, target cloud.Path, names map[string]string) (changed, skipped []string, err error) {
	config, err := project.Load(projectPath)
	if err != nil {
		return nil, nil, err
	}
	link := target.Org + "/" + target.Project
	if config.Cloud == "" {
		// Linking changes what cloud.* means: before it, such references
		// are local ones.
		for _, environment := range config.EnvironmentNames() {
			for variable, ref := range config.Environments[environment] {
				if strings.HasPrefix(ref.String(), cloud.ReferencePrefix) {
					return nil, nil, fmt.Errorf("%s in %s reads the local secret %s; linking a cloud project would make it a cloud reference. Rename that secret first", variable, environment, ref)
				}
			}
		}
		if err := project.SetCloud(projectPath, link); err != nil {
			return nil, nil, err
		}
		config.Cloud = link
	}
	for _, environment := range config.EnvironmentNames() {
		variables := make([]string, 0, len(config.Environments[environment]))
		for variable := range config.Environments[environment] {
			variables = append(variables, variable)
		}
		sort.Strings(variables)
		for _, variable := range variables {
			name, ok := names[config.Environments[environment][variable].String()]
			if !ok {
				continue
			}
			// The short form reads the linked project's environment of the
			// same name; anything else names the secret in full.
			text := cloud.ReferencePrefix + name
			if config.Cloud != link || environment != target.Env {
				text = cloud.ReferencePrefix + strings.Join([]string{target.Org, target.Project, target.Env, name}, ".")
			}
			ref, err := domain.ParseReference(text)
			if _, _, pathErr := cloud.ReferencePath(text, config.Cloud, environment); err != nil || pathErr != nil {
				skipped = append(skipped, environment+" "+variable)
				continue
			}
			if err := project.SetBinding(projectPath, environment, variable, ref); err != nil {
				return changed, skipped, err
			}
			changed = append(changed, environment+" "+variable)
		}
	}
	return changed, skipped, nil
}

// cloudImportTeam moves the values of the project's team file into one
// cloud environment.
func (w Workspace) cloudImportTeam(argv []string) int {
	a, err := parseArgs(argv, nil, []string{"relink", "yes"}, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError(cloudImportUsage)
	}
	target, err := cloud.ParsePath(a.positional[0], false)
	if err != nil {
		return w.cloudFail(err)
	}
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	values, err := w.Session.TeamValues(projectPath)
	if err != nil {
		if errors.Is(err, team.ErrNotRecipient) {
			w.status().Error("You are not a member of this project's team file, so you cannot read what to move.")
			return 1
		}
		return w.fail(err, "The team file is unavailable.")
	}
	defer func() {
		for _, v := range values {
			wipe(v)
		}
	}()
	if len(values) == 0 {
		w.status().Info(team.FileName + " holds no values to move.")
		return 0
	}
	refs := make([]string, 0, len(values))
	for ref := range values {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	names, err := cloudNames(refs)
	if err != nil {
		return w.cloudFail(err)
	}
	out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
	renamed := map[string][]byte{}
	for _, ref := range refs {
		fmt.Fprintf(out, "%s\t-> %s/%s\n", ref, target, names[ref])
		renamed[names[ref]] = values[ref]
	}
	out.Flush()
	if !a.flags["yes"] && !w.confirmChoice(fmt.Sprintf("Store these %d %s in %s?", len(refs), plural(len(refs), "value", "values"), target)) {
		w.status().Error("Nothing was stored.")
		return 1
	}
	ctx, cancel := cloudContext()
	defer cancel()
	written, err := w.cloudService().SetAll(ctx, target, renamed)
	if err != nil {
		if len(written) > 0 {
			w.status().Warn(fmt.Sprintf("%d of %d were stored before this failed; running it again stores the rest.", len(written), len(refs)))
		}
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("Stored %d %s in %s; %d already there.", len(written), plural(len(written), "value", "values"), target, len(refs)-len(written)))
	if !a.flags["relink"] {
		w.status().Info("envrune.yml still reads them from " + team.FileName + ". Run this again with --relink to point it at the cloud.")
		return 0
	}
	changed, skipped, err := relinkTeam(projectPath, target, names)
	if err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("Pointed %d %s of envrune.yml at the cloud.", len(changed), plural(len(changed), "variable", "variables")))
	for _, variable := range skipped {
		w.status().Warn(fmt.Sprintf("%s could not be written as a cloud reference; link it by hand.", variable))
	}
	if len(skipped) == 0 {
		w.status().Info(fmt.Sprintf("Once everyone who needs these values is a member of %s, delete %s.", target.Org, team.FileName))
		w.status().Warn("Its members, past and present, can still read what it held, in the Git history too. Replace any value that should not stay known.")
	}
	return 0
}
