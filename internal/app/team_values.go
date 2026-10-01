package app

import (
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
)

// TeamValues returns every value of the project's team file, by reference,
// for moving them to EnvRune Cloud. The caller wipes the values.
func (s *Session) TeamValues(projectPath string) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return nil, err
	}
	if !team.Exists(team.Path(projectPath)) {
		return nil, ErrNoTeamFile
	}
	src := s.sources()
	defer src.close()
	file, err := src.teamFile(projectPath)
	if err != nil {
		return nil, err
	}
	values := map[string][]byte{}
	for _, name := range file.References() {
		ref, err := domain.ParseReference(name)
		if err != nil {
			continue
		}
		if value, ok := file.Value(ref); ok {
			values[name] = value
		}
	}
	return values, nil
}
