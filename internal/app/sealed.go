package app

import "github.com/YagoLagrottiBracco/envrune/internal/cloud"

// UseSealed gives the placeholders that stand for sensitive cloud secrets,
// by "org/project/env/name", for as long as a command runs. References to
// those secrets resolve to the placeholders.
func (s *Session) UseSealed(placeholders map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = placeholders
}

// sensitiveLocked tells sensitive secrets from missing ones, from what this
// device last heard from the server. The caller holds s.mu.
func (s *Session) sensitiveLocked() func(cloud.Path) bool {
	if s.vault == nil {
		return nil
	}
	v := s.vault
	return func(path cloud.Path) bool {
		raw := v.CloudState()
		defer wipe(raw)
		return cloud.CachedSensitive(raw, path)
	}
}
