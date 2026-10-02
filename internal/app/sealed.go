package app

import "github.com/YagoLagrottiBracco/envrune/internal/cloud"

// Seal gives the placeholders that stand for sensitive cloud secrets, by
// "org/project/env/name", for as long as a command runs: references to
// those secrets resolve to the placeholders. It returns the function that
// takes them back. Several commands, such as the services of `up`, may each
// seal their own.
func (s *Session) Seal(placeholders map[string][]byte) (unseal func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed == nil {
		s.sealed = map[string][]byte{}
	}
	for path, placeholder := range placeholders {
		s.sealed[path] = placeholder
	}
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for path, placeholder := range placeholders {
			if string(s.sealed[path]) == string(placeholder) {
				delete(s.sealed, path)
			}
		}
	}
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
