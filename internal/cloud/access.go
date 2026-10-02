package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// Access for a limited time (docs/cloud-operations.md). A member asks for
// environments they do not have; an administrator's CLI signs the wider
// scope, as for any change of scope, and the server records until when it
// holds. When the time is up the server stops serving the wider part by
// itself; signing the scope back and starting new keys takes this CLI.

// AccessGrant is a request for access and what became of it.
type AccessGrant struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Scope       []string   `json:"scope"`
	Minutes     int        `json:"minutes"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"` // pending, approved, denied, ended
	RequestedAt time.Time  `json:"requested_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	BaseScope   []string   `json:"base_scope"`
	ListedAt    *time.Time `json:"listed_at"`
}

// Expired reports that the grant's time is up and the server already
// refuses the member, while their membership still says the wider scope.
func (g AccessGrant) Expired() bool {
	return g.Status == "approved" && g.ExpiresAt != nil && !now().Before(*g.ExpiresAt)
}

// Open reports that the grant still waits for an administrator's CLI: to
// sign the scope back, or to list what was fetched.
func (g AccessGrant) Open() bool {
	return g.Expired() || (g.Status == "ended" && g.ListedAt == nil && g.BaseScope != nil)
}

func (c *Client) decideAccess(ctx context.Context, id, decision string, base []string, out any) error {
	in := map[string]any{"decision": decision}
	if decision == "approve" {
		in["base_scope"] = nonNil(base)
	}
	return c.call(ctx, http.MethodPost, "/access/"+url.PathEscape(id), nil, in, out)
}

// RequestAccess asks for environments, as project/environment or
// project/*, for a duration. It returns the request's id.
func (s *Service) RequestAccess(ctx context.Context, org string, scope []string, d time.Duration, reason string) (string, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return "", err
	}
	minutes := int(d.Minutes())
	if minutes < 5 || minutes > 7*24*60 {
		return "", errors.New("access is asked for 5 minutes to 7 days")
	}
	var out struct {
		ID string `json:"id"`
	}
	err = c.call(ctx, http.MethodPost, "/orgs/"+url.PathEscape(org)+"/access", nil, map[string]any{"scope": scope, "minutes": minutes, "reason": reason}, &out)
	return out.ID, err
}

// AccessList returns the organization's requests, newest first: one's own,
// or everyone's for owners and admins.
func (s *Service) AccessList(ctx context.Context, org string) ([]AccessGrant, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	var out []AccessGrant
	return out, c.call(ctx, http.MethodGet, "/orgs/"+url.PathEscape(org)+"/access", nil, nil, &out)
}

func (s *Service) accessGrant(ctx context.Context, org, id string) (*AccessGrant, error) {
	grants, err := s.AccessList(ctx, org)
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if g.ID == id {
			return &g, nil
		}
	}
	return nil, fmt.Errorf("no request %s in %s", id, org)
}

// ApproveAccess signs the member's membership with what they asked for
// added to their scope, shares the keys, and records until when it holds.
func (s *Service) ApproveAccess(ctx context.Context, org, id string) (time.Time, error) {
	g, err := s.accessGrant(ctx, org, id)
	if err != nil {
		return time.Time{}, err
	}
	if g.Status != "pending" {
		return time.Time{}, fmt.Errorf("request %s is not waiting; it is %s", id, g.Status)
	}
	member, err := s.verifiedMember(ctx, org, g.UserID)
	if err != nil {
		return time.Time{}, err
	}
	wider := slices.Clone(member.Scope)
	for _, entry := range g.Scope {
		if !slices.Contains(wider, entry) {
			wider = append(wider, entry)
		}
	}
	if _, err := s.certify(ctx, org, g.UserID, member.AccountKey, member.Role, wider); err != nil {
		return time.Time{}, err
	}
	_, c, err := s.signedIn()
	if err != nil {
		return time.Time{}, err
	}
	var out struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := c.decideAccess(ctx, id, "approve", member.Scope, &out); err != nil {
		return time.Time{}, fmt.Errorf("the wider scope was signed, but its end was not recorded; set the member's scope back with `member set`: %w", err)
	}
	return out.ExpiresAt, nil
}

// DenyAccess refuses a waiting request.
func (s *Service) DenyAccess(ctx context.Context, org, id string) error {
	_, c, err := s.signedIn()
	if err != nil {
		return err
	}
	return c.decideAccess(ctx, id, "deny", nil, nil)
}

// EndAccess signs the member's scope back to what it was before a grant,
// starts new keys for the environments they lose, and has the server list
// what they fetched meanwhile. It ends a grant early, and finishes one
// whose time is up, which the server already stopped serving.
func (s *Service) EndAccess(ctx context.Context, org, id string) (*Handover, error) {
	g, err := s.accessGrant(ctx, org, id)
	if err != nil {
		return nil, err
	}
	h := &Handover{}
	switch {
	case g.Status == "approved":
		member, err := s.verifiedMember(ctx, org, g.UserID)
		if err != nil {
			return nil, err
		}
		if h, err = s.certify(ctx, org, g.UserID, member.AccountKey, member.Role, g.BaseScope); err != nil {
			return h, err
		}
	case g.Status == "ended" && g.ListedAt == nil && g.BaseScope != nil:
		// The scope was already signed back; only the list is missing.
	default:
		return nil, fmt.Errorf("request %s gives no access to end; it is %s", id, g.Status)
	}
	_, c, err := s.signedIn()
	if err != nil {
		return h, err
	}
	return h, c.decideAccess(ctx, id, "close", nil, nil)
}
