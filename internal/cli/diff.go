package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

// diff compares the variables two environments define. It reads only
// envrune.yml, so it needs no unlock and never sees a value.
func (w Workspace) diff(argv []string) int {
	a, err := parseArgs(argv, nil, nil, false)
	if err != nil || len(a.positional) != 2 {
		return w.usageError("diff <environment> <environment>")
	}
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	config, err := project.Load(projectPath)
	if err != nil {
		return w.fail(err, "The project configuration is invalid.")
	}
	left, right := a.positional[0], a.positional[1]
	for _, environment := range []string{left, right} {
		if config.Environments[environment] == nil {
			return w.fail(&app.MissingEnvironmentError{Environment: environment, Available: config.EnvironmentNames()}, "Unknown environment.")
		}
	}
	a1, a2 := config.Environments[left], config.Environments[right]
	var onlyLeft, onlyRight, shared []string
	for name := range a1 {
		if _, ok := a2[name]; !ok {
			onlyLeft = append(onlyLeft, name)
		} else if a1[name] == a2[name] {
			shared = append(shared, fmt.Sprintf("%s → %s", name, a1[name]))
		}
	}
	for name := range a2 {
		if _, ok := a1[name]; !ok {
			onlyRight = append(onlyRight, name)
		}
	}
	report := NewPresenter(w.Stdout, w.Stdout, os.Getenv)
	section := func(title string, names []string) {
		if len(names) == 0 {
			return
		}
		sort.Strings(names)
		fmt.Fprintf(w.Stdout, "%s (%d):\n", title, len(names))
		for _, name := range names {
			fmt.Fprintln(w.Stdout, "  "+name)
		}
	}
	section("Only in "+left, onlyLeft)
	section("Only in "+right, onlyRight)
	section("Same reference in both", shared)
	if len(shared) > 0 {
		report.Warn(fmt.Sprintf("%s and %s share %d %s. That is fine for values that do not differ, but not for credentials that should be separate.", left, right, len(shared), plural(len(shared), "reference", "references")))
	}
	if len(onlyLeft)+len(onlyRight) > 0 {
		report.Error(fmt.Sprintf("%s and %s define different variables. Link the missing ones with `envrune link <VAR> <reference> --env <environment>`.", left, right))
		return 1
	}
	report.Success(fmt.Sprintf("%s and %s define the same %d %s.", left, right, len(a1), plural(len(a1), "variable", "variables")))
	return 0
}
