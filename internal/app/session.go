package app

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/dotenv"
	"github.com/envrune/envrune/internal/generator"
	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/runner"
	"github.com/envrune/envrune/internal/vault"
)

var ErrSessionClosed = errors.New("session is closed")

// Session owns one opened vault for the lifetime of an interactive shell.
type Session struct {
	mu    sync.Mutex
	vault *vault.Opened
}

func OpenSession(path string, password []byte) (*Session, error) {
	v, err := vault.Open(path, password)
	if err != nil {
		return nil, err
	}
	return &Session{vault: v}, nil
}

func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault != nil {
		s.vault.Close()
		s.vault = nil
	}
}

func (s *Session) Set(rawReference string, value []byte) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	return s.mutate(func(v *vault.Opened) error {
		if err := v.Put(ref, value, time.Now()); err != nil {
			return err
		}
		return v.Commit()
	})
}

func (s *Session) Generate(rawReference string, length int) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	value, err := generator.New(length)
	if err != nil {
		return err
	}
	defer wipe(value)
	return s.mutate(func(v *vault.Opened) error {
		if err := v.Put(ref, value, time.Now()); err != nil {
			return err
		}
		return v.Commit()
	})
}

func (s *Session) Import(entries []dotenv.Entry) (int, error) {
	type plannedEntry struct {
		ref   domain.Reference
		value []byte
	}
	planned := make([]plannedEntry, 0, len(entries))
	seen := make(map[domain.Reference]struct{})
	for _, entry := range entries {
		if !project.VariableName(entry.Name) {
			return 0, ErrInvalidImport
		}
		ref, err := importReference(entry.Name)
		if err != nil {
			return 0, ErrInvalidImport
		}
		if _, exists := seen[ref]; exists {
			return 0, ErrInvalidImport
		}
		seen[ref] = struct{}{}
		planned = append(planned, plannedEntry{ref: ref, value: entry.Value})
	}
	err := s.mutate(func(v *vault.Opened) error {
		for _, entry := range planned {
			if err := v.Put(entry.ref, entry.value, time.Now()); err != nil {
				return err
			}
		}
		return v.Commit()
	})
	if err != nil {
		return 0, err
	}
	return len(planned), nil
}

func (s *Session) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return nil, ErrSessionClosed
	}
	refs := s.vault.References()
	out := make([]string, len(refs))
	for i, ref := range refs {
		out[i] = ref.String()
	}
	sort.Strings(out)
	return out, nil
}

func (s *Session) Link(projectPath, environment, variable, rawReference string) error {
	if environment == "" || !project.VariableName(variable) {
		return project.ErrInvalidConfig
	}
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	return s.mutate(func(v *vault.Opened) error {
		if err := project.UpdateAtomic(projectPath, func(config *project.Config) error {
			if config.Environments[environment] == nil {
				config.Environments[environment] = map[string]domain.Reference{}
			}
			config.Environments[environment][variable] = ref
			return nil
		}); err != nil {
			return err
		}
		v.RegisterProject(projectPath)
		return v.Commit()
	})
}

func (s *Session) Usage(rawReference string) ([]Usage, error) {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return nil, ErrSessionClosed
	}
	return usageFor(s.vault.Projects(), ref), nil
}

func (s *Session) ResolveEnvironment(projectPath, environment string) ([]runner.Pair, error) {
	config, err := project.Load(projectPath)
	if err != nil {
		return nil, err
	}
	mappings, ok := config.Environments[environment]
	if !ok {
		return nil, ErrMissingEnvironment
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return nil, ErrSessionClosed
	}
	variables := make([]string, 0, len(mappings))
	for variable := range mappings {
		variables = append(variables, variable)
	}
	sort.Strings(variables)
	pairs := make([]runner.Pair, 0, len(variables))
	for _, variable := range variables {
		value, exists := s.vault.Value(mappings[variable])
		if !exists {
			wipePairs(pairs)
			return nil, ErrMissingSecret
		}
		pairs = append(pairs, runner.Pair{Name: variable, Value: value})
	}
	return pairs, nil
}

func (s *Session) Snapshot() DashboardSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return snapshot(s.vault)
}

func (s *Session) mutate(change func(*vault.Opened) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return ErrSessionClosed
	}
	return change(s.vault)
}

func usageFor(paths []string, ref domain.Reference) []Usage {
	var out []Usage
	for _, path := range paths {
		config, err := project.Load(path)
		if err != nil {
			continue
		}
		for environment, mappings := range config.Environments {
			for variable, mapped := range mappings {
				if mapped == ref {
					out = append(out, Usage{path, environment, variable})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProjectPath != out[j].ProjectPath {
			return out[i].ProjectPath < out[j].ProjectPath
		}
		if out[i].Environment != out[j].Environment {
			return out[i].Environment < out[j].Environment
		}
		return out[i].Variable < out[j].Variable
	})
	return out
}
