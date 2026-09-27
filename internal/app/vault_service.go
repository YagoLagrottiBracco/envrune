package app

import (
	"errors"
	"runtime"
	"sort"
	"time"

	crypto "github.com/envrune/envrune/internal/crypto"
	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/project"
	"github.com/envrune/envrune/internal/vault"
)

var ErrPasswordConfirmation = errors.New("master password confirmation does not match")

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
