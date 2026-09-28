package app

import (
	"sort"
	"sync"

	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/vault"
)

// DashboardSnapshot deliberately has no field that can carry a secret value.
// The HTTP layer depends on this metadata boundary, never on an opened vault.
type DashboardSnapshot struct {
	References []ReferenceMetadata
	Projects   []ProjectMetadata
}

type ReferenceMetadata struct {
	Name  string
	Usage []Usage
}

type ProjectMetadata struct {
	Name         string
	Path         string
	Unavailable  bool
	Environments []EnvironmentMetadata
}

type EnvironmentMetadata struct {
	Name     string
	Bindings []BindingMetadata
}

type BindingMetadata struct {
	Variable  string
	Reference string
	Available bool
}

// Dashboard owns the vault only for the foreground UI command's lifetime.
// Keeping it open also keeps its lock: finish the UI before another CLI write.
type Dashboard struct {
	mu    sync.Mutex
	vault *vault.Opened
}

func OpenDashboard(path string, password []byte) (*Dashboard, error) {
	v, err := vault.Open(path, password)
	if err != nil {
		return nil, err
	}
	return &Dashboard{vault: v}, nil
}

func (d *Dashboard) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.vault != nil {
		d.vault.Close()
		d.vault = nil
	}
}

func (d *Dashboard) Snapshot() DashboardSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return snapshot(d.vault)
}

func snapshot(v *vault.Opened) DashboardSnapshot {
	var snapshot DashboardSnapshot
	if v == nil {
		return snapshot
	}
	references := v.References()
	sort.Slice(references, func(i, j int) bool { return references[i] < references[j] })
	index := make(map[string]int, len(references))
	for _, ref := range references {
		index[ref.String()] = len(snapshot.References)
		snapshot.References = append(snapshot.References, ReferenceMetadata{Name: ref.String()})
	}
	paths := v.Projects()
	sort.Strings(paths)
	for _, path := range paths {
		metadata := ProjectMetadata{Path: path}
		config, err := project.Load(path)
		if err != nil {
			metadata.Unavailable = true
			snapshot.Projects = append(snapshot.Projects, metadata)
			continue
		}
		metadata.Name = config.Project
		environments := make([]string, 0, len(config.Environments))
		for environment := range config.Environments {
			environments = append(environments, environment)
		}
		sort.Strings(environments)
		for _, environment := range environments {
			env := EnvironmentMetadata{Name: environment}
			variables := make([]string, 0, len(config.Environments[environment]))
			for variable := range config.Environments[environment] {
				variables = append(variables, variable)
			}
			sort.Strings(variables)
			for _, variable := range variables {
				ref := config.Environments[environment][variable].String()
				i, available := index[ref]
				env.Bindings = append(env.Bindings, BindingMetadata{Variable: variable, Reference: ref, Available: available})
				if available {
					snapshot.References[i].Usage = append(snapshot.References[i].Usage, Usage{ProjectPath: path, Environment: environment, Variable: variable})
				}
			}
			metadata.Environments = append(metadata.Environments, env)
		}
		snapshot.Projects = append(snapshot.Projects, metadata)
	}
	return snapshot
}
