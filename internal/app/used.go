package app

import (
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

// NoteUsed records today as the last day a command was given the vault's
// secrets that one environment of envrune.yml links, so doctor can tell
// which secrets nobody uses anymore (docs/project-file.md). It writes the
// vault at most once a day per secret.
func (s *Session) NoteUsed(projectPath, environment string, now time.Time) error {
	config, err := project.Load(projectPath)
	if err != nil {
		return err
	}
	refs := make([]domain.Reference, 0, len(config.Environments[environment]))
	for _, ref := range config.Environments[environment] {
		refs = append(refs, ref)
	}
	day := now.Format(time.DateOnly)
	needed := false
	if err := s.read(func(v *vault.Opened) error {
		needed = v.UsedBefore(refs, day)
		return nil
	}); err != nil || !needed {
		return err
	}
	return s.mutate(func(v *vault.Opened) error {
		v.NoteUsed(refs, day)
		return nil
	})
}
