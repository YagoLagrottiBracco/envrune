package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// An emergency is for a project whose secrets must be assumed known
// (docs/cloud-operations.md). The server takes the keys away from everyone
// but the device that asks; this device then makes new ones, for itself
// alone. Access comes back when an administrator shares the new keys.

// Emergency is what declaring one did.
type Emergency struct {
	// Tokens are the machine tokens that could reach the project, now revoked.
	Tokens []string
	// Rotated are the environments given a new key, held by this device only.
	Rotated []string
	// Left are the environments this device had no key for, so it could
	// make no new one: their old key is gone from the server all the same.
	Left []string
	// Secrets is how many values are listed to replace.
	Secrets int
}

func (c *Client) emergency(ctx context.Context, org, project, deviceID string) (tokens []string, secrets int, err error) {
	var out struct {
		Tokens  []string `json:"tokens"`
		Secrets int      `json:"secrets"`
	}
	path := "/orgs/" + url.PathEscape(org) + "/projects/" + url.PathEscape(project) + "/emergency"
	err = c.call(ctx, http.MethodPost, path, nil, map[string]string{"device": deviceID}, &out)
	return out.Tokens, out.Secrets, err
}

// Emergency takes a project's keys away from every device but this one and
// starts new ones. Only an owner may. The values stay as they are until
// each is replaced; the guided rotation lists all of them.
func (s *Service) Emergency(ctx context.Context, org, project string) (*Emergency, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return nil, err
	}
	me, err := v.member(st.UserID)
	if err != nil {
		return nil, err
	}
	if me.Role != cloudcrypto.RoleOwner {
		return nil, errors.New("only an owner declares an emergency")
	}
	var found *projectJSON
	for i := range v.snap.Projects {
		if v.snap.Projects[i].Slug == project {
			found = &v.snap.Projects[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no project %s in %s", project, org)
	}
	// Open what this device can, while the state is the one it knows.
	out := &Emergency{}
	current := map[string]*opened{}
	defer func() {
		for _, o := range current {
			o.wipe()
		}
	}()
	for i := range found.Environments {
		e := &found.Environments[i]
		o, err := s.openCurrent(ctx, c, st, device, v, found, e, true)
		switch {
		case err == nil:
			current[e.Slug] = o
		case errors.Is(err, ErrNoKey) && len(e.Secrets) == 0:
			current[e.Slug] = nil
		default:
			out.Left = append(out.Left, project+"/"+e.Slug)
		}
	}
	if out.Tokens, out.Secrets, err = c.emergency(ctx, org, project, device.DeviceID); err != nil {
		return nil, err
	}
	if v, err = s.view(ctx, c, org); err != nil {
		return out, err
	}
	// New keys for this device and this owner's recovery recipient only.
	mine := func(r recipient) bool {
		return !r.token && r.cert.UserID == st.UserID && (r.cert.RecipientID == device.DeviceID || r.cert.Kind == cloudcrypto.KindRecovery)
	}
	for slug, o := range current {
		p, e, err := v.environment(project, slug)
		if err != nil {
			return out, err
		}
		if _, err := s.rotateFor(ctx, c, st, device, v, p, e, o, mine); err != nil {
			return out, fmt.Errorf("%s/%s: %w", project, slug, err)
		}
		out.Rotated = append(out.Rotated, project+"/"+slug)
	}
	return out, nil
}
