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
	"github.com/YagoLagrottiBracco/envrune/internal/redact"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

var (
	ErrSessionClosed = errors.New("session is closed")
	// ErrNoVault means the session runs from a team identity only, as in CI,
	// and the command needs the personal vault.
	ErrNoVault    = errors.New("this command needs the personal vault")
	ErrNoTeamFile = errors.New("the project has no team file (envrune.team.json)")
)

// Session keeps one unlocked vault in memory for the lifetime of a command
// or an interactive shell. It does not hold the vault file lock, so other
// shells and commands can use the vault at the same time: reads pick up
// their changes and writes are merged on top of them.
type Session struct {
	mu       sync.Mutex
	vault    *vault.Opened
	identity string // team identity when there is no vault
	closed   bool
}

func OpenSession(path string, password []byte) (*Session, error) {
	v, err := vault.Open(path, password)
	if err != nil {
		return nil, err
	}
	return &Session{vault: v}, nil
}

// NewSession wraps a vault opened by other means, such as the agent key.
func NewSession(v *vault.Opened) *Session { return &Session{vault: v} }

// NewIdentitySession resolves only team references, with a team identity
// taken from the environment. CI uses it when there is no personal vault.
func NewIdentitySession(identity string) *Session { return &Session{identity: identity} }

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
	s.closed = true
}

// HasVault reports whether the session has the personal vault.
func (s *Session) HasVault() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vault != nil
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

// Rotate replaces the value with a generated one of the given length, or of
// the current length when length is zero. The old value stays in history.
func (s *Session) Rotate(rawReference string, length int) (int, error) {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return 0, err
	}
	err = s.mutate(func(v *vault.Opened) error {
		current, ok := v.Value(ref)
		if !ok {
			return vault.ErrUnknownReference
		}
		if length == 0 {
			length = len(current)
			if length < 16 || length > 512 {
				length = 32
			}
		}
		wipe(current)
		value, err := generator.New(length)
		if err != nil {
			return err
		}
		defer wipe(value)
		return v.Put(ref, value, time.Now())
	})
	return length, err
}

func (s *Session) Rollback(rawReference string) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	return s.mutate(func(v *vault.Opened) error { return v.Rollback(ref, time.Now()) })
}

func (s *Session) Remove(rawReference string) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	return s.mutate(func(v *vault.Opened) error { return v.Remove(ref) })
}

func (s *Session) SetMeta(rawReference string, change vault.MetaChange) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	return s.mutate(func(v *vault.Opened) error { return v.SetMeta(ref, change) })
}

func (s *Session) Info(rawReference string) (vault.Info, error) {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return vault.Info{}, err
	}
	var info vault.Info
	err = s.read(func(v *vault.Opened) error {
		var ok bool
		if info, ok = v.Info(ref); !ok {
			return vault.ErrUnknownReference
		}
		return nil
	})
	return info, err
}

func (s *Session) Infos() ([]vault.Info, error) {
	var out []vault.Info
	err := s.read(func(v *vault.Opened) error {
		for _, ref := range v.References() {
			info, _ := v.Info(ref)
			out = append(out, info)
		}
		return nil
	})
	return out, err
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

// Has reports whether a reference resolves, from the vault or, for team
// references, from the project's team file.
func (s *Session) Has(projectPath, rawReference string) (bool, error) {
	value, err := s.Reveal(projectPath, rawReference)
	if errors.Is(err, vault.ErrUnknownReference) {
		return false, nil
	}
	wipe(value)
	return err == nil, err
}

// Reveal returns a copy of one secret value. The caller wipes it.
func (s *Session) Reveal(projectPath, rawReference string) ([]byte, error) {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return nil, err
	}
	src := s.sources()
	defer src.close()
	value, ok, err := src.value(projectPath, ref)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, vault.ErrUnknownReference
	}
	return value, nil
}

// Secrets returns every value the session can read, named by reference, so
// guard and scan can look for them. Team values from the project's team file
// are included when projectPath is set and this user is a member. The caller
// wipes the values.
func (s *Session) Secrets(projectPath string) ([]redact.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return nil, err
	}
	src := s.sources()
	defer src.close()
	var out []redact.Secret
	if s.vault != nil {
		for _, ref := range s.vault.References() {
			if value, ok := s.vault.Value(ref); ok {
				out = append(out, redact.Secret{Name: ref.String(), Value: value})
			}
		}
	}
	if projectPath != "" {
		if file, err := src.teamFile(projectPath); err == nil {
			for _, name := range file.References() {
				ref, err := domain.ParseReference(name)
				if err != nil {
					continue
				}
				if value, ok := file.Value(ref); ok {
					out = append(out, redact.Secret{Name: name, Value: value})
				}
			}
		}
	}
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
	if err := project.SetBinding(projectPath, environment, variable, ref); err != nil {
		return err
	}
	if !s.HasVault() {
		return nil
	}
	return s.mutate(func(v *vault.Opened) error {
		v.RegisterProject(projectPath)
		return nil
	})
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

// Resolve returns the variables of one environment. An empty environment
// means the default one.
func (s *Session) Resolve(projectPath, environment string) (Resolved, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return Resolved{}, err
	}
	src := s.sources()
	defer src.close()
	return resolve(src, projectPath, environment)
}

func (s *Session) ResolveEnvironment(projectPath, environment string) ([]runner.Pair, error) {
	resolved, err := s.Resolve(projectPath, environment)
	return resolved.Pairs, err
}

// Key returns the vault's data key for the agent or the system keychain.
func (s *Session) Key() ([]byte, error) {
	var key []byte
	err := s.read(func(v *vault.Opened) error {
		key = v.Key()
		return nil
	})
	return key, err
}

func (s *Session) VaultPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault == nil {
		return ""
	}
	return s.vault.Path()
}

func (s *Session) ChangePassword(password []byte) error {
	return s.mutate(func(v *vault.Opened) error { return v.ChangePassword(password) })
}

func (s *Session) ResetRecovery() ([]byte, error) {
	var recovery []byte
	err := s.mutate(func(v *vault.Opened) (err error) {
		recovery, err = v.ResetRecovery()
		return err
	})
	return recovery, err
}

func (s *Session) HasRecovery() (bool, error) {
	var has bool
	err := s.read(func(v *vault.Opened) error {
		has = v.HasRecovery()
		return nil
	})
	return has, err
}

// Identity returns the team identity, creating one in the vault if needed.
func (s *Session) Identity() (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", false, ErrSessionClosed
	}
	if s.vault == nil {
		if s.identity == "" {
			return "", false, ErrNoVault
		}
		return s.identity, false, nil
	}
	if err := s.vault.Refresh(); err != nil {
		return "", false, err
	}
	if existing := s.vault.Identity(); len(existing) > 0 {
		return string(existing), false, nil
	}
	identity, err := team.NewIdentity()
	if err != nil {
		return "", false, err
	}
	err = s.vault.Update(func(v *vault.Opened) error {
		if len(v.Identity()) == 0 {
			v.SetIdentity([]byte(identity))
		}
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return string(s.vault.Identity()), true, nil
}

func (s *Session) Snapshot() DashboardSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault != nil {
		_ = s.vault.Refresh() // on failure, show the last state that was read
	}
	return snapshot(s.vault)
}

func (s *Session) sources() *sources {
	return &sources{vault: s.vault, identity: s.identityLocked}
}

// identityLocked returns the team identity without creating one. The caller
// holds s.mu.
func (s *Session) identityLocked() (string, error) {
	if s.vault != nil {
		if identity := s.vault.Identity(); len(identity) > 0 {
			return string(identity), nil
		}
		return "", team.ErrNotRecipient
	}
	if s.identity == "" {
		return "", team.ErrNotRecipient
	}
	return s.identity, nil
}

// refresh loads changes from other processes. The caller holds s.mu.
func (s *Session) refresh() error {
	if s.closed {
		return ErrSessionClosed
	}
	if s.vault == nil {
		return nil
	}
	return s.vault.Refresh()
}

// read runs use against the latest committed state of the vault.
func (s *Session) read(use func(*vault.Opened) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	if s.vault == nil {
		return ErrNoVault
	}
	if err := s.vault.Refresh(); err != nil {
		return err
	}
	return use(s.vault)
}

func (s *Session) mutate(change func(*vault.Opened) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	if s.vault == nil {
		return ErrNoVault
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
