package cloud

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// A value replaced on the server reaches a device when the device pulls.
// Freshen is what makes that happen without anyone asking: before a command
// starts, and while one runs, the device asks the server only for version
// numbers and pulls the environments whose numbers moved. See
// docs/managed-keys.md.

// envVersions is one environment in the answer of GET /versions.
type envVersions struct {
	Epoch   uint64            `json:"epoch"`
	Secrets map[string]uint64 `json:"secrets"`
}

func (c *Client) versions(ctx context.Context, envIDs []string) (map[string]envVersions, error) {
	out := map[string]envVersions{}
	return out, c.call(ctx, http.MethodGet, "/versions", url.Values{"env": envIDs}, nil, &out)
}

// behind reports whether a cached environment differs from what the server
// has now: another epoch, or another set of secrets or versions.
func (cached *CachedEnv) behind(now envVersions) bool {
	if cached.Payload.Epoch != now.Epoch || len(cached.Payload.Secrets) != len(now.Secrets) {
		return true
	}
	for _, s := range cached.Payload.Secrets {
		if now.Secrets[s.Name] != s.Version {
			return true
		}
	}
	return false
}

// FreshenCheckTimeout bounds the question a command asks before it starts,
// so a slow or unreachable server does not hold it up.
const FreshenCheckTimeout = 1500 * time.Millisecond

// Freshen brings this device's copies of the environments in paths up to
// date and returns the ones it pulled. It asks the server for version
// numbers, waiting at most check for the answer, and pulls only what moved,
// what this device has no copy of yet, and what would soon be too old for
// the organization's offline limit. Signed out, it does nothing.
//
// A device that cannot reach the server gets an error and keeps its copies;
// callers that work offline ignore it.
func (s *Service) Freshen(ctx context.Context, paths []Path, check time.Duration) ([]Path, error) {
	st, c, err := s.signedIn()
	if err != nil || st.DeviceID == "" || !st.DeviceApproved {
		return nil, nil
	}
	// The same moment online carries the notes of use kept meanwhile.
	if len(st.Use) > 0 {
		reportCtx, cancel := context.WithTimeout(ctx, check)
		_, _ = s.ReportUse(reportCtx)
		cancel()
	}
	var pull []Path
	asked := map[string]Path{} // environment id → path
	for _, path := range paths {
		path.Name = ""
		var cached *CachedEnv
		if o := st.Orgs[path.Org]; o != nil {
			cached = o.Cache[path.cacheKey()]
			if cached != nil && cached.Payload != nil && o.OfflineDays > 0 &&
				now().Sub(cached.FetchedAt) > time.Duration(o.OfflineDays)*12*time.Hour {
				// Past half of the offline limit: renew it while online.
				cached = nil
			}
		}
		if cached == nil || cached.Payload == nil {
			pull = append(pull, path)
			continue
		}
		asked[cached.EnvironmentID] = path
	}
	if len(asked) > 0 {
		ids := make([]string, 0, len(asked))
		for id := range asked {
			ids = append(ids, id)
		}
		checkCtx, cancel := context.WithTimeout(ctx, check)
		current, err := c.versions(checkCtx, ids)
		cancel()
		if err != nil {
			return nil, err
		}
		for id, path := range asked {
			// An environment missing from the answer is one this member no
			// longer sees; pulling says so in the server's words.
			if now, ok := current[id]; !ok || st.Orgs[path.Org].Cache[path.cacheKey()].behind(now) {
				pull = append(pull, path)
			}
		}
	}
	var pulled []Path
	for _, path := range pull {
		if _, err := s.Pull(ctx, path, false); err != nil {
			return pulled, err
		}
		pulled = append(pulled, path)
	}
	return pulled, nil
}
