package app

import (
	"errors"
	"runtime"
	"sort"
	"strings"
	"time"

	crypto "github.com/envrune/envrune/internal/crypto"
	"github.com/envrune/envrune/internal/dotenv"
	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/generator"
	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/runner"
	"github.com/envrune/envrune/internal/vault"
)

var ErrPasswordConfirmation = errors.New("master password confirmation does not match")
var ErrInvalidImport = errors.New("invalid dotenv import")
var ErrMissingEnvironment = errors.New("environment configuration not found")
var ErrMissingSecret = errors.New("configured secret is unavailable")

type VaultService struct{}

type Usage struct {
	ProjectPath string
	Environment string
	Variable    string
}

func (VaultService) Init(path string, password, confirmation []byte) error {
	if string(password) != string(confirmation) {
		return ErrPasswordConfirmation
	}
	return vault.Create(path, password, crypto.DefaultKDFParams(runtime.NumCPU()))
}

func (VaultService) Set(path string, password []byte, rawReference string, value []byte) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	v, err := vault.Open(path, password)
	if err != nil {
		return err
	}
	defer v.Close()
	if err := v.Put(ref, value, time.Now()); err != nil {
		return err
	}
	return v.Commit()
}

func (VaultService) Generate(path, rawReference string, length int, password []byte) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil { return err }
	value, err := generator.New(length)
	if err != nil { return err }
	defer wipe(value)
	v, err := vault.Open(path, password)
	if err != nil { return err }
	defer v.Close()
	if err := v.Put(ref, value, time.Now()); err != nil { return err }
	return v.Commit()
}

func (VaultService) Import(path string, entries []dotenv.Entry, password []byte) (int, error) {
	type plannedEntry struct { ref domain.Reference; value []byte }
	planned := make([]plannedEntry, 0, len(entries))
	seen := make(map[domain.Reference]struct{})
	for _, entry := range entries {
		if !project.VariableName(entry.Name) { return 0, ErrInvalidImport }
		ref, err := importReference(entry.Name)
		if err != nil { return 0, ErrInvalidImport }
		if _, exists := seen[ref]; exists { return 0, ErrInvalidImport }
		seen[ref] = struct{}{}
		planned = append(planned, plannedEntry{ref: ref, value: entry.Value})
	}
	v, err := vault.Open(path, password)
	if err != nil { return 0, err }
	defer v.Close()
	for _, entry := range planned { if err := v.Put(entry.ref, entry.value, time.Now()); err != nil { return 0, err } }
	if err := v.Commit(); err != nil { return 0, err }
	return len(planned), nil
}

func (VaultService) ResolveEnvironment(vaultPath, projectPath, environment string, password []byte) ([]runner.Pair, error) {
	config, err := project.Load(projectPath)
	if err != nil { return nil, err }
	mappings, ok := config.Environments[environment]
	if !ok { return nil, ErrMissingEnvironment }
	v, err := vault.Open(vaultPath, password)
	if err != nil { return nil, err }
	defer v.Close()
	variables := make([]string, 0, len(mappings))
	for variable := range mappings { variables = append(variables, variable) }
	sort.Strings(variables)
	pairs := make([]runner.Pair, 0, len(variables))
	for _, variable := range variables {
		value, exists := v.Value(mappings[variable])
		if !exists { wipePairs(pairs); return nil, ErrMissingSecret }
		pairs = append(pairs, runner.Pair{Name: variable, Value: value})
	}
	return pairs, nil
}

func importReference(name string) (domain.Reference, error) {
	return domain.ParseReference("import.var-" + strings.ReplaceAll(strings.ToLower(name), "_", "-"))
}

func wipePairs(pairs []runner.Pair) { for _, pair := range pairs { wipe(pair.Value) } }
func wipe(value []byte) { for i := range value { value[i] = 0 } }

func (VaultService) List(path string, password []byte) ([]string, error) {
	v, err := vault.Open(path, password)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	refs := v.References()
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.String()
	}
	sort.Strings(out)
	return out, nil
}

func (VaultService) Link(vaultPath, projectPath, environment, variable, rawReference string, password []byte) error {
	if environment == "" || !project.VariableName(variable) {
		return project.ErrInvalidConfig
	}
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return err
	}
	defer v.Close()
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
}

func (VaultService) Usage(vaultPath, rawReference string, password []byte) ([]Usage, error) {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return nil, err
	}
	v, err := vault.Open(vaultPath, password)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	var out []Usage
	for _, path := range v.Projects() {
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
	return out, nil
}
