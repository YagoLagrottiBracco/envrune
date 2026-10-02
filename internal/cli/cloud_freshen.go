package cli

import (
	"fmt"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

// cloudPaths lists the cloud environments that one environment of
// envrune.yml reads values from.
func cloudPaths(config project.Config, environment string) []cloud.Path {
	var paths []cloud.Path
	seen := map[cloud.Path]bool{}
	for _, ref := range config.Environments[environment] {
		path, isCloud, err := cloud.ReferencePath(ref.String(), config.Cloud, environment)
		if !isCloud || err != nil {
			continue
		}
		path.Name = ""
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return paths
}

// freshen brings the cloud values a command is about to use up to date, so
// a value replaced by its owner is used from the next run on, with nobody
// pulling by hand. It waits briefly for the server; offline, or signed out,
// the command starts with the copy this device has. It returns the cloud
// environments the command reads.
func (w Workspace) freshen(projectPath, environment string) []cloud.Path {
	config, err := project.Load(projectPath)
	if err != nil || config.Cloud == "" {
		return nil
	}
	chosen, err := app.ChooseEnvironment(config, environment)
	if err != nil {
		return nil
	}
	paths := cloudPaths(config, chosen)
	if len(paths) == 0 {
		return nil
	}
	ctx, cancel := cloudContext()
	defer cancel()
	pulled, _ := w.cloudService().Freshen(ctx, paths, cloud.FreshenCheckTimeout)
	for _, path := range pulled {
		w.status().Info(fmt.Sprintf("Synced %s: its values changed since this device last pulled.", path))
	}
	return paths
}

// noteUse records, in the vault, that a command was given cloud values its
// user may use but not see. The device reports the note when it is next
// online; see docs/managed-keys.md. Names and the time only.
func noteUse(store cloud.Store, projectPath string, resolved app.Resolved) {
	// The vault notes the day its own secrets were last used, whatever the
	// role: doctor points at the ones nobody uses anymore.
	if session, ok := store.(*app.Session); ok && session.HasVault() {
		_ = session.NoteUsed(projectPath, resolved.Environment, time.Now())
	}
	if !resolved.Restricted {
		return
	}
	config, err := project.Load(projectPath)
	if err != nil || config.Cloud == "" {
		return
	}
	names := map[cloud.Path][]string{}
	for _, ref := range config.Environments[resolved.Environment] {
		path, isCloud, err := cloud.ReferencePath(ref.String(), config.Cloud, resolved.Environment)
		if !isCloud || err != nil {
			continue
		}
		name := path.Name
		path.Name = ""
		names[path] = append(names[path], name)
	}
	service := &cloud.Service{Store: store}
	for path, used := range names {
		_ = service.RecordUse(path, used)
	}
}
