package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// A sensitive secret never reaches a member's machine: its value is sealed
// to the server's proxy identity, and the server puts it into the member's
// requests to the hosts its owner allowed. It is the one kind of secret the
// server can read, chosen per secret by an owner or admin who was shown
// what that means. See docs/managed-keys.md.

// sensitiveJSON is a sensitive secret as GET /orgs/{slug} lists it: what a
// device needs to verify who marked it and where it may go, and no
// ciphertext.
type sensitiveJSON struct {
	EnvironmentID  string   `json:"environment_id"`
	Name           string   `json:"name"`
	Version        uint64   `json:"version"`
	Hosts          []string `json:"hosts"`
	ProxyRecipient string   `json:"proxy_recipient"`
	SealedHash     []byte   `json:"sealed_hash"`
	WriterUserID   string   `json:"writer_user_id"`
	WriterDeviceID string   `json:"writer_device_id"`
	Signature      []byte   `json:"signature"`
}

func (s sensitiveJSON) record(orgID, projectID string) *cloudcrypto.SensitiveRecord {
	return &cloudcrypto.SensitiveRecord{OrgID: orgID, ProjectID: projectID, EnvironmentID: s.EnvironmentID, Name: s.Name, Version: s.Version,
		Hosts: s.Hosts, ProxyRecipient: s.ProxyRecipient, SealedHash: s.SealedHash, WriterUserID: s.WriterUserID, WriterDeviceID: s.WriterDeviceID,
		Signature: s.Signature}
}

// SensitiveInfo is a sensitive secret as members see it.
type SensitiveInfo struct {
	Name    string
	Version uint64
	Hosts   []string
	// Verified says that an owner or admin of the environment signed the
	// secret with these hosts for the proxy identity this device pinned.
	Verified bool
}

// ErrProxyChanged means the server presents another proxy identity than the
// one this device was shown and pinned.
var ErrProxyChanged = errors.New("the server's proxy identity is not the one this device trusted; do not seal values to it until you know why")

func (c *Client) proxyRecipient(ctx context.Context) (string, error) {
	var out struct {
		Recipient string `json:"recipient"`
	}
	if err := c.send(ctx, http.MethodGet, "/proxy", nil, "", nil, &out); err != nil {
		return "", err
	}
	return out.Recipient, nil
}

func (c *Client) putSensitive(ctx context.Context, envID string, r *cloudcrypto.SensitiveRecord) error {
	return c.call(ctx, http.MethodPost, "/environments/"+url.PathEscape(envID)+"/sensitive", nil, map[string]any{
		"name": r.Name, "version": r.Version, "hosts": r.Hosts, "proxy_recipient": r.ProxyRecipient, "sealed": r.Sealed,
		"device": r.WriterDeviceID, "signature": r.Signature,
	}, nil)
}

// ProxyIdentity is the server's proxy identity as a person checks it.
type ProxyIdentity struct {
	Fingerprint string
	// Pinned says this device already trusted this identity; a new one must
	// be confirmed by the person before SetSensitive.
	Pinned bool
}

// Proxy asks the server for its proxy identity. One that differs from the
// identity this device pinned is refused: the server could be presenting a
// key of someone else's to have values sealed to it.
func (s *Service) Proxy(ctx context.Context) (*ProxyIdentity, error) {
	st, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	recipient, err := c.proxyRecipient(ctx)
	if err != nil {
		return nil, err
	}
	if st.ProxyRecipient != "" && st.ProxyRecipient != recipient {
		return nil, ErrProxyChanged
	}
	return &ProxyIdentity{Fingerprint: cloudcrypto.ProxyFingerprint(recipient), Pinned: st.ProxyRecipient == recipient}, nil
}

// SetSensitive writes the next version of a sensitive secret: value, sealed
// on this device to the server's proxy identity, to be sent only to hosts.
// fingerprint is the proxy identity the person confirmed (Proxy); it is
// pinned on first use, and a server presenting another one is refused.
//
// Only owners and admins of the environment may do this, and no member's
// device can read the value back, this one included.
func (s *Service) SetSensitive(ctx context.Context, path Path, value []byte, hosts []string, fingerprint string) (uint64, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return 0, err
	}
	v, err := s.view(ctx, c, path.Org)
	if err != nil {
		return 0, err
	}
	p, e, err := v.environment(path.Project, path.Env)
	if err != nil {
		return 0, err
	}
	me, err := v.member(st.UserID)
	if err != nil {
		return 0, err
	}
	if !mayMarkSensitive(me, p.Slug, e.Slug) {
		return 0, fmt.Errorf("only owners and admins of %s/%s set sensitive secrets", p.Slug, e.Slug)
	}
	for _, sec := range e.Secrets {
		if sec.Name == path.Name {
			return 0, fmt.Errorf("%s already exists as an ordinary secret, which members have read; use another name", path)
		}
	}
	recipient, err := c.proxyRecipient(ctx)
	if err != nil {
		return 0, err
	}
	switch {
	case st.ProxyRecipient != "" && st.ProxyRecipient != recipient:
		return 0, ErrProxyChanged
	case cloudcrypto.ProxyFingerprint(recipient) != fingerprint:
		return 0, fmt.Errorf("the server's proxy identity changed after you were shown it: %w", cloudcrypto.ErrUntrusted)
	}
	var current uint64
	for _, sec := range v.snap.Sensitive {
		if sec.EnvironmentID == e.ID && sec.Name == path.Name {
			current = sec.Version
		}
	}
	record, err := device.SealSensitive(v.trust.OrgID, p.ID, e.ID, path.Name, current+1, value, hosts, recipient)
	if err != nil {
		return 0, err
	}
	// Pin before sending: from here on this device seals only to this one.
	if err := s.update(func(st *State) error {
		if st.ProxyRecipient != "" && st.ProxyRecipient != recipient {
			return ErrProxyChanged
		}
		st.ProxyRecipient = recipient
		return nil
	}); err != nil {
		return 0, err
	}
	if err := c.putSensitive(ctx, e.ID, record); err != nil {
		return 0, err
	}
	return record.Version, nil
}

func mayMarkSensitive(m cloudcrypto.Membership, project, env string) bool {
	return (m.Role == cloudcrypto.RoleOwner || m.Role == cloudcrypto.RoleAdmin) && m.CanAdminister(project, env)
}

// sensitive lists an environment's sensitive secrets, verifying each one's
// signature through the chain to the pinned roots and against the proxy
// identity this device pinned, if it pinned one.
func (v *view) sensitive(p *projectJSON, e *environmentJSON, pinnedProxy string) []SensitiveInfo {
	var out []SensitiveInfo
	for _, sec := range v.snap.Sensitive {
		if sec.EnvironmentID != e.ID {
			continue
		}
		info := SensitiveInfo{Name: sec.Name, Version: sec.Version, Hosts: sec.Hosts}
		key, err := v.verifier(p, e, nil).signer(sec.WriterUserID, sec.WriterDeviceID, func(m cloudcrypto.Membership) bool {
			return mayMarkSensitive(m, p.Slug, e.Slug)
		})
		if err == nil && sec.record(v.trust.OrgID, p.ID).Verify(key) == nil && (pinnedProxy == "" || pinnedProxy == sec.ProxyRecipient) {
			info.Verified = true
		}
		out = append(out, info)
	}
	return out
}
