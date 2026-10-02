package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// After a value is replaced, its owner wants to know who already has the
// new one. The server knows when each value was written and when each
// device and token last fetched the environment; a reader whose last fetch
// is older than a value is behind on it. See docs/managed-keys.md.

type statusJSON struct {
	Secrets []struct {
		Name            string     `json:"name"`
		Version         uint64     `json:"version"`
		WrittenAt       time.Time  `json:"written_at"`
		TransitionUntil *time.Time `json:"transition_until"`
	} `json:"secrets"`
	Fetches []struct {
		UserID    *string   `json:"user_id"`
		DeviceID  *string   `json:"device_id"`
		TokenID   *string   `json:"token_id"`
		LastFetch time.Time `json:"last_fetch"`
	} `json:"fetches"`
}

func (c *Client) environmentStatus(ctx context.Context, envID string) (*statusJSON, error) {
	var out statusJSON
	return &out, c.call(ctx, http.MethodGet, "/environments/"+url.PathEscape(envID)+"/status", nil, nil, &out)
}

func (c *Client) setTransition(ctx context.Context, envID, name string, until *time.Time) error {
	path := "/environments/" + url.PathEscape(envID) + "/secrets/" + url.PathEscape(name) + "/transition"
	return c.call(ctx, http.MethodPut, path, nil, map[string]any{"until": until}, nil)
}

// EnvStatus is an environment's current values and who has them.
type EnvStatus struct {
	Secrets []SecretStatus
	Readers []ReaderStatus
}

type SecretStatus struct {
	Name      string
	Version   uint64
	WrittenAt time.Time
	// TransitionUntil is until when the previous value is expected to work
	// where it was issued; zero when nobody said.
	TransitionUntil time.Time
}

// ReaderStatus is a device or a machine token that fetched the environment.
type ReaderStatus struct {
	UserID, DeviceID string // a member's device, or
	TokenID          string // a machine token
	LastFetch        time.Time
	// Behind names the secrets written after LastFetch: this reader still
	// has their previous values. Stale names the ones of those whose
	// transition has passed, so the previous value is expected to fail.
	Behind, Stale []string
}

// Name is how the reader is shown.
func (r ReaderStatus) Name() string {
	if r.TokenID != "" {
		return "token " + r.TokenID
	}
	return r.UserID + " (" + r.DeviceID + ")"
}

// EnvironmentStatus reports who has the current values of an environment.
// It is the server's account: it shows that ciphertext reached a device,
// not that a process there was restarted with it.
func (s *Service) EnvironmentStatus(ctx context.Context, path Path) (*EnvStatus, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, path.Org)
	if err != nil {
		return nil, err
	}
	_, e, err := v.environment(path.Project, path.Env)
	if err != nil {
		return nil, err
	}
	raw, err := c.environmentStatus(ctx, e.ID)
	if err != nil {
		return nil, err
	}
	out := &EnvStatus{}
	for _, sec := range raw.Secrets {
		status := SecretStatus{Name: sec.Name, Version: sec.Version, WrittenAt: sec.WrittenAt}
		if sec.TransitionUntil != nil {
			status.TransitionUntil = *sec.TransitionUntil
		}
		out.Secrets = append(out.Secrets, status)
	}
	for _, f := range raw.Fetches {
		reader := ReaderStatus{LastFetch: f.LastFetch}
		switch {
		case f.TokenID != nil:
			reader.TokenID = *f.TokenID
		case f.UserID != nil && f.DeviceID != nil:
			reader.UserID, reader.DeviceID = *f.UserID, *f.DeviceID
		default:
			continue
		}
		for _, sec := range out.Secrets {
			if !sec.WrittenAt.After(f.LastFetch) {
				continue
			}
			reader.Behind = append(reader.Behind, sec.Name)
			if !sec.TransitionUntil.IsZero() && now().After(sec.TransitionUntil) {
				reader.Stale = append(reader.Stale, sec.Name)
			}
		}
		out.Readers = append(out.Readers, reader)
	}
	slices.SortFunc(out.Readers, func(a, b ReaderStatus) int { return strings.Compare(a.Name(), b.Name()) })
	return out, nil
}

// SetTransition records until when the value before the current one of a
// secret is expected to keep working where it was issued. It informs
// people; EnvRune cannot keep an old value working or stop it from working.
func (s *Service) SetTransition(ctx context.Context, path Path, until time.Time) error {
	_, c, err := s.signedIn()
	if err != nil {
		return err
	}
	v, err := s.view(ctx, c, path.Org)
	if err != nil {
		return err
	}
	_, e, err := v.environment(path.Project, path.Env)
	if err != nil {
		return err
	}
	if !until.After(now()) {
		return fmt.Errorf("the transition must end in the future")
	}
	return c.setTransition(ctx, e.ID, path.Name, &until)
}
