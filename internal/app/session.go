package app

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/dotenv"
	"github.com/YagoLagrottiBracco/envrune/internal/generator"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

var ErrSessionClosed = errors.New("session is closed")

// Session keeps one unlocked vault in memory for the lifetime of an
// interactive shell. It does not hold the vault file lock, so other shells and
// commands can use the vault at the same time: reads pick up their changes and
// writes are merged on top of them.
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
	return s.mutate(func(v *vault.Opened) error { return v.Put(ref, value, time.Now()) })
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
	return s.mutate(func(v *vault.Opened) error { return v.Put(ref, value, time.Now()) })
}

func (s *Session) Import(entries []dotenv.Entry) (int, error) {
	planned, err := planImport(entries)
	if err != nil {
		return 0, err
	}
	if err := s.mutate(putAll(planned)); err != nil {
		return 0, err
	}
	return len(planned), nil
}

func (s *Session) List() ([]string, error) {
	var out []string
	err := s.read(func(v *vault.Opened) error {
		out = referenceNames(v)
		return nil
	})
	return out, err
}

func (s *Session) Link(projectPath, environment, variable, rawReference string) error {
	change, err := linkChange(projectPath, environment, variable, rawReference)
	if err != nil {
		return err
	}
	return s.mutate(change)
}

func (s *Session) Usage(rawReference string) ([]Usage, error) {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return nil, err
	}
	var out []Usage
	err = s.read(func(v *vault.Opened) error {
		out = usageFor(v.Projects(), ref)
		return nil
	})
	return out, err
}

func (s *Session) ResolveEnvironment(projectPath, environment string) ([]runner.Pair, error) {
	var pairs []runner.Pair
	err := s.read(func(v *vault.Opened) (err error) {
		pairs, err = resolveEnvironment(v, projectPath, environment)
		return err
	})
	return pairs, err
}

func (s *Session) Snapshot() DashboardSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault != nil {
		_ = s.vault.Refresh() // on failure, show the last state that was read
	}
	return snapshot(s.vault)
}

// read runs use against the latest committed state of the vault.
func (s *Session) read(use func(*vault.Opened) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return ErrSessionClosed
	}
	if err := s.vault.Refresh(); err != nil {
		return err
	}
	return use(s.vault)
}

func (s *Session) mutate(change func(*vault.Opened) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return ErrSessionClosed
	}
	return s.vault.Update(change)
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
