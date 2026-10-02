package cloud

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// The server sees fetches, not use. When a command injects values the user
// may use but not see, the device notes which secrets and when, in the
// vault, and reports the notes the next time it reaches the server. They
// are the device's own account: someone who changes the CLI can skip them.
// See docs/managed-keys.md.

// UseRecord is one command that used secrets of one environment.
type UseRecord struct {
	Org     string    `json:"org"`
	Project string    `json:"project"`
	Env     string    `json:"env"`
	Names   []string  `json:"names"`
	At      time.Time `json:"at"`
}

// maxPendingUse bounds what a device that never comes online keeps; the
// oldest notes go first.
const maxPendingUse = 500

// RecordUse notes that a command was given the named secrets of path's
// environment. It only writes to the vault.
func (s *Service) RecordUse(path Path, names []string) error {
	if len(names) == 0 {
		return nil
	}
	names = slices.Clone(names)
	slices.Sort(names)
	return s.update(func(st *State) error {
		st.Use = append(st.Use, UseRecord{Org: path.Org, Project: path.Project, Env: path.Env, Names: names, At: now().UTC()})
		if extra := len(st.Use) - maxPendingUse; extra > 0 {
			st.Use = st.Use[extra:]
		}
		return nil
	})
}

func (c *Client) reportUse(ctx context.Context, envID, deviceID string, uses []UseRecord) error {
	rows := make([]map[string]any, 0, len(uses))
	for _, u := range uses {
		rows = append(rows, map[string]any{"names": u.Names, "at": u.At.Format(time.RFC3339Nano)})
	}
	return c.call(ctx, http.MethodPost, "/environments/"+url.PathEscape(envID)+"/use", nil, map[string]any{"device": deviceID, "uses": rows}, nil)
}

// ReportUse sends the notes RecordUse kept and forgets the ones the server
// took. Notes for an environment this device has no copy of, or may no
// longer use, are dropped: the server would not take them. It returns how
// many it sent.
func (s *Service) ReportUse(ctx context.Context) (int, error) {
	st, c, err := s.signedIn()
	if err != nil || st.DeviceID == "" || len(st.Use) == 0 {
		return 0, nil
	}
	byEnv := map[string][]UseRecord{} // environment id → notes
	for _, u := range st.Use {
		if o := st.Orgs[u.Org]; o != nil {
			if cached := o.Cache[Path{Project: u.Project, Env: u.Env}.cacheKey()]; cached != nil {
				byEnv[cached.EnvironmentID] = append(byEnv[cached.EnvironmentID], u)
			}
		}
	}
	sent := 0
	for id, uses := range byEnv {
		for len(uses) > 0 {
			batch := uses[:min(len(uses), 200)]
			uses = uses[len(batch):]
			err := c.reportUse(ctx, id, st.DeviceID, batch)
			var api *APIError
			if err != nil && !(asAPIError(err, &api) && (api.Status == http.StatusForbidden || api.Status == http.StatusNotFound)) {
				return sent, err // out of reach: keep the notes for next time
			}
			if err == nil {
				sent += len(batch)
			}
		}
	}
	// Everything noted before this call was sent or refused for good.
	reported := len(st.Use)
	return sent, s.update(func(fresh *State) error {
		fresh.Use = fresh.Use[min(reported, len(fresh.Use)):]
		return nil
	})
}
