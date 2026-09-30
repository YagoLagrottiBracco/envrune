package app

import (
	"errors"
	"runtime"
	"sort"
	"strings"
	"time"

	crypto "github.com/YagoLagrottiBracco/envrune/internal/crypto"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/dotenv"
	"github.com/YagoLagrottiBracco/envrune/internal/generator"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

var ErrPasswordConfirmation = errors.New("master password confirmation does not match")
var ErrInvalidImport = errors.New("invalid dotenv import")

type VaultService struct{}

type Usage struct {
	ProjectPath string
	Environment string
	Variable    string
}

// Init creates the vault and returns its recovery key, to be shown once.
func (VaultService) Init(path string, password, confirmation []byte) ([]byte, error) {
	if string(password) != string(confirmation) {
		return nil, ErrPasswordConfirmation
	}
	return vault.Create(path, password, crypto.DefaultKDFParams(runtime.NumCPU()))
}

func (VaultService) Set(path string, password []byte, rawReference string, value []byte) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	return withVault(path, password, func(v *vault.Opened) error {
		return v.Update(func(v *vault.Opened) error { return v.Put(ref, value, time.Now()) })
	})
}

func (VaultService) Generate(path, rawReference string, length int, password []byte) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	value, err := generator.New(length)
	if err != nil {
		return err
	}
	defer wipe(value)
	return withVault(path, password, func(v *vault.Opened) error {
		return v.Update(func(v *vault.Opened) error { return v.Put(ref, value, time.Now()) })
	})
}

func (VaultService) Import(path string, entries []dotenv.Entry, password []byte) (int, error) {
	planned, err := planImport(entries)
	if err != nil {
		return 0, err
	}
	err = withVault(path, password, func(v *vault.Opened) error { return v.Update(putAll(planned)) })
	if err != nil {
		return 0, err
	}
	return len(planned), nil
}

func (VaultService) ResolveEnvironment(vaultPath, projectPath, environment string, password []byte) ([]runner.Pair, error) {
	session, err := OpenSession(vaultPath, password)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return session.ResolveEnvironment(projectPath, environment)
}

func (VaultService) List(path string, password []byte) ([]string, error) {
	var out []string
	err := withVault(path, password, func(v *vault.Opened) error {
		out = referenceNames(v)
		return nil
	})
	return out, err
}

func (VaultService) Link(vaultPath, projectPath, environment, variable, rawReference string, password []byte) error {
	session, err := OpenSession(vaultPath, password)
	if err != nil {
		return err
	}
	defer session.Close()
	return session.Link(projectPath, environment, variable, rawReference)
}

func (VaultService) Usage(vaultPath, rawReference string, password []byte) ([]Usage, error) {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return nil, err
	}
	var out []Usage
	err = withVault(vaultPath, password, func(v *vault.Opened) error {
		out = usageFor(v.Projects(), ref)
		return nil
	})
	return out, err
}

func withVault(path string, password []byte, use func(*vault.Opened) error) error {
	v, err := vault.Open(path, password)
	if err != nil {
		return err
	}
	defer v.Close()
	return use(v)
}

type plannedEntry struct {
	ref   domain.Reference
	value []byte
}

func planImport(entries []dotenv.Entry) ([]plannedEntry, error) {
	planned := make([]plannedEntry, 0, len(entries))
	seen := make(map[domain.Reference]struct{})
	for _, entry := range entries {
		if !project.VariableName(entry.Name) {
			return nil, ErrInvalidImport
		}
		ref, err := importReference(entry.Name)
		if err != nil {
			return nil, ErrInvalidImport
		}
		if _, exists := seen[ref]; exists {
			return nil, ErrInvalidImport
		}
		seen[ref] = struct{}{}
		planned = append(planned, plannedEntry{ref: ref, value: entry.Value})
	}
	return planned, nil
}

func putAll(planned []plannedEntry) func(*vault.Opened) error {
	return func(v *vault.Opened) error {
		for _, entry := range planned {
			if err := v.Put(entry.ref, entry.value, time.Now()); err != nil {
				return err
			}
		}
		return nil
	}
}

func referenceNames(v *vault.Opened) []string {
	refs := v.References()
	out := make([]string, len(refs))
	for i, ref := range refs {
		out[i] = ref.String()
	}
	sort.Strings(out)
	return out
}

func importReference(name string) (domain.Reference, error) {
	return domain.ParseReference("import.var-" + strings.ReplaceAll(strings.ToLower(name), "_", "-"))
}

func wipePairs(pairs []runner.Pair) {
	for _, pair := range pairs {
		wipe(pair.Value)
	}
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
