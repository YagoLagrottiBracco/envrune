package cloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// view is an organization as this device verifies it: the server's
// snapshot, checked against the roots pinned the first time and every
// membership certificate this device has seen.
type view struct {
	snap  *Snapshot
	trust cloudcrypto.Trust
	certs []*cloudcrypto.MembershipCertificate
	// FirstSeen is set when this call pinned the roots.
	firstSeen bool
}

// view fetches an organization and pins or checks its roots. Certificates
// are merged into the ones kept, so a removal seen once stays in force even
// if the server hides it later.
func (s *Service) view(ctx context.Context, c *Client, slug string) (*view, error) {
	snap, err := c.snapshot(ctx, slug)
	if err != nil {
		return nil, err
	}
	v := &view{snap: snap}
	err = s.update(func(st *State) error {
		o := st.org(slug)
		if o.ID == "" {
			if len(snap.Roots) == 0 {
				return fmt.Errorf("the server sent %s without roots: %w", slug, cloudcrypto.ErrUntrusted)
			}
			o.ID = snap.ID
			for _, r := range snap.Roots {
				o.Roots[r.UserID] = r.AccountKey
			}
			v.firstSeen = true
		} else if o.ID != snap.ID {
			return ErrOrgChanged
		}
		o.Certificates = mergeCerts(o.Certificates, snap.Certificates)
		v.trust = cloudcrypto.Trust{OrgID: o.ID, Roots: pinned(o.Roots)}
		v.certs = certificates(o.Certificates)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

// mergeCerts adds the certificates of more that kept lacks, by signature.
func mergeCerts(kept, more []certJSON) []certJSON {
	for _, c := range more {
		if !slices.ContainsFunc(kept, func(k certJSON) bool { return bytes.Equal(k.Signature, c.Signature) }) {
			kept = append(kept, c)
		}
	}
	return kept
}

func (v *view) verifier(p *projectJSON, e *environmentJSON, payload *EnvPayload) *verifier {
	var devices []deviceJSON
	if payload != nil {
		devices = payload.Devices
	}
	return &verifier{orgID: v.trust.OrgID, projectID: p.ID, envID: e.ID, project: p.Slug, env: e.Slug,
		trust: v.trust, certs: v.certs, devices: append(slices.Clone(v.snap.Devices), devices...)}
}

func (v *view) member(userID string) (cloudcrypto.Membership, error) {
	m, err := v.trust.Verify(v.certs, userID)
	if err != nil {
		return m, fmt.Errorf("you are not a verified member of %s: %w", v.snap.Slug, err)
	}
	return m, nil
}

func (v *view) environment(project, env string) (*projectJSON, *environmentJSON, error) {
	p, e, ok := v.snap.environment(project, env)
	if !ok {
		return nil, nil, fmt.Errorf("no environment %s/%s/%s", v.snap.Slug, project, env)
	}
	return p, e, nil
}

// recipient is a certificate that may receive an environment's key.
type recipient struct {
	cert  *cloudcrypto.RecipientCertificate
	token bool
}

// recipients lists every device, recovery recipient, and machine token the
// verified chain allows to use an environment. Anything the server added
// on its own fails verification and is left out.
func (v *view) recipients(p *projectJSON, e *environmentJSON) []recipient {
	var out []recipient
	for _, d := range v.snap.Devices {
		if d.RevokedAt != nil || d.Signature == nil {
			continue
		}
		cert := d.certificate()
		if v.trust.VerifyRecipient(v.certs, cert, p.Slug, e.Slug) == nil {
			out = append(out, recipient{cert: cert})
		}
	}
	for _, t := range v.snap.Tokens {
		expires, err := time.Parse(time.RFC3339, t.ExpiresAt)
		if t.RevokedAt != nil || (err == nil && expires.Before(time.Now())) {
			continue
		}
		cert := t.certificate()
		if v.trust.VerifyRecipient(v.certs, cert, p.Slug, e.Slug) == nil {
			out = append(out, recipient{cert: cert, token: true})
		}
	}
	return out
}

func wrapAll(device *cloudcrypto.Device, key *cloudcrypto.EnvironmentKey, recipients []recipient) ([]map[string]any, error) {
	rows := make([]map[string]any, 0, len(recipients))
	for _, r := range recipients {
		w, err := device.Wrap(key, r.cert)
		if err != nil {
			return nil, err
		}
		rows = append(rows, wrappedToJSON(w, r.token))
	}
	return rows, nil
}

// ---------------------------------------------------------------- organizations

// Org is an organization as `envrune cloud org show` prints it.
type Org struct {
	ID, Slug, Name string
	Role           string
	Roots          []Root
	Members        []Member
	Projects       []Project
	FirstSeen      bool // the roots were pinned by this call: compare them out of band
}

type Root struct{ UserID, Fingerprint string }

type Member struct {
	UserID, Role string
	Scope        []string
	Fingerprint  string
	Verified     bool // the certificate chain reaches a pinned root
}

type Project struct {
	Slug         string
	Environments []Environment
}

type Environment struct {
	Slug          string
	Epoch         uint64
	NeedsRotation bool
	Secrets       []SecretInfo
}

type SecretInfo struct {
	Name    string
	Version uint64
}

func (s *Service) Orgs(ctx context.Context) ([]OrgSummary, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	return c.orgs(ctx)
}

// CreateOrg founds an organization; this account's key becomes its root.
func (s *Service) CreateOrg(ctx context.Context, slug, name string) (*Org, error) {
	st, c, _, err := s.ready()
	if err != nil {
		return nil, err
	}
	account, err := st.account()
	if err != nil {
		return nil, err
	}
	if err := c.createOrg(ctx, slug, name); err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, slug)
	if err != nil {
		return nil, err
	}
	if root := v.trust.Roots[st.UserID]; len(v.trust.Roots) != 1 || !root.Equal(account.Public) {
		return nil, fmt.Errorf("the server pinned another root for %s than your account key: %w", slug, cloudcrypto.ErrUntrusted)
	}
	return v.describe(st.UserID), nil
}

func (s *Service) ShowOrg(ctx context.Context, slug string) (*Org, error) {
	st, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, slug)
	if err != nil {
		return nil, err
	}
	return v.describe(st.UserID), nil
}

func (v *view) describe(self string) *Org {
	o := &Org{ID: v.snap.ID, Slug: v.snap.Slug, Name: v.snap.Name, FirstSeen: v.firstSeen}
	for user, key := range v.trust.Roots {
		o.Roots = append(o.Roots, Root{UserID: user, Fingerprint: cloudcrypto.Fingerprint(key)})
	}
	for _, m := range v.snap.Members {
		if m.Role == cloudcrypto.RoleRemoved {
			continue
		}
		member := Member{UserID: m.UserID, Role: m.Role, Scope: m.Scope}
		if verified, err := v.trust.Verify(v.certs, m.UserID); err == nil {
			member.Role, member.Scope, member.Verified = verified.Role, verified.Scope, true
			member.Fingerprint = cloudcrypto.Fingerprint(verified.AccountKey)
		}
		if m.UserID == self {
			o.Role = member.Role
		}
		o.Members = append(o.Members, member)
	}
	for _, p := range v.snap.Projects {
		project := Project{Slug: p.Slug}
		for _, e := range p.Environments {
			env := Environment{Slug: e.Slug, Epoch: e.Epoch, NeedsRotation: e.NeedsRotation}
			for _, sec := range e.Secrets {
				env.Secrets = append(env.Secrets, SecretInfo{Name: sec.Name, Version: sec.CurrentVersion})
			}
			project.Environments = append(project.Environments, env)
		}
		o.Projects = append(o.Projects, project)
	}
	return o
}

// ---------------------------------------------------------------- members

// Account is another user's public account key, for adding them.
type Account struct {
	UserID      string
	Key         ed25519.PublicKey
	Fingerprint string
}

// LookupAccount asks the server for an account key by email. The server
// could answer with a key of its own: the caller must have the admin
// compare Fingerprint with the new member before SetMember.
func (s *Service) LookupAccount(ctx context.Context, email string) (*Account, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	found, err := c.lookupAccount(ctx, email)
	if err != nil {
		return nil, err
	}
	if len(found.AccountKey) != ed25519.PublicKeySize {
		return nil, cloudcrypto.ErrMalformed
	}
	return &Account{UserID: found.UserID, Key: found.AccountKey, Fingerprint: cloudcrypto.Fingerprint(found.AccountKey)}, nil
}

// AddMember signs a membership for an account whose fingerprint the admin
// confirmed, then shares with the member's devices the environment keys
// this device holds and may share. It returns how many keys it shared.
func (s *Service) AddMember(ctx context.Context, org string, account *Account, role string, scope []string) (int, error) {
	return s.certify(ctx, org, account.UserID, account.Key, role, scope)
}

// ChangeMember signs a new role or scope for a current member, whose key
// comes from their verified membership rather than from the server.
func (s *Service) ChangeMember(ctx context.Context, org, userID, role string, scope []string) (int, error) {
	if role == cloudcrypto.RoleRemoved {
		return 0, errors.New("use RemoveMember")
	}
	_, c, err := s.signedIn()
	if err != nil {
		return 0, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return 0, err
	}
	current, err := v.trust.Verify(v.certs, userID)
	if err != nil {
		return 0, fmt.Errorf("%s is not a verified member: %w", userID, err)
	}
	return s.certify(ctx, org, userID, current.AccountKey, role, scope)
}

func (s *Service) certify(ctx context.Context, org, userID string, key ed25519.PublicKey, role string, scope []string) (int, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return 0, err
	}
	account, err := st.account()
	if err != nil {
		return 0, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return 0, err
	}
	cert, err := account.Certify(v.trust.OrgID, userID, key, role, scope)
	if err != nil {
		return 0, err
	}
	if err := c.addMembership(ctx, org, cert); err != nil {
		return 0, err
	}
	return s.shareAll(ctx, c, st, device, org)
}

// RemoveMember signs a removal, then rotates every environment the member
// could use and this device administers, so they cannot read anything
// written afterwards. The values they already knew still need rotating
// (`envrune cloud rotation`). It returns the environments it rotated.
func (s *Service) RemoveMember(ctx context.Context, org, userID string) ([]string, error) {
	st, c, _, err := s.ready()
	if err != nil {
		return nil, err
	}
	if userID == st.UserID {
		return nil, errors.New("you cannot remove yourself; ask another owner or admin")
	}
	account, err := st.account()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return nil, err
	}
	removed, err := v.trust.Verify(v.certs, userID)
	if err != nil {
		return nil, fmt.Errorf("%s is not a verified member: %w", userID, err)
	}
	cert, err := account.Certify(v.trust.OrgID, userID, removed.AccountKey, cloudcrypto.RoleRemoved, nil)
	if err != nil {
		return nil, err
	}
	if err := c.addMembership(ctx, org, cert); err != nil {
		return nil, err
	}
	me, err := v.member(st.UserID)
	if err != nil {
		return nil, err
	}
	var rotated []string
	for _, p := range v.snap.Projects {
		for _, e := range p.Environments {
			if removed.CanUse(p.Slug, e.Slug) && me.CanAdminister(p.Slug, e.Slug) {
				if _, err := s.Rotate(ctx, org, p.Slug, e.Slug); err != nil {
					return rotated, fmt.Errorf("%s/%s: %w", p.Slug, e.Slug, err)
				}
				rotated = append(rotated, p.Slug+"/"+e.Slug)
			}
		}
	}
	return rotated, nil
}

// Share wraps every environment key this device holds, in environments it
// administers, for every verified recipient that may use it: members added
// or devices approved since, and machine tokens. It returns how many
// environments it shared.
func (s *Service) Share(ctx context.Context, org string) (int, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return 0, err
	}
	return s.shareAll(ctx, c, st, device, org)
}

func (s *Service) shareAll(ctx context.Context, c *Client, st *State, device *cloudcrypto.Device, org string) (int, error) {
	v, err := s.view(ctx, c, org)
	if err != nil {
		return 0, err
	}
	me, err := v.member(st.UserID)
	if err != nil {
		return 0, err
	}
	shared := 0
	for _, p := range v.snap.Projects {
		for _, e := range p.Environments {
			if !me.CanAdminister(p.Slug, e.Slug) {
				continue
			}
			payload, err := c.fetchEnvironment(ctx, e.ID, device.DeviceID)
			if err != nil {
				return shared, err
			}
			key, err := v.verifier(&p, &e, payload).key(payload, map[string]age.Identity{device.DeviceID: device.Identity}, st.UserID)
			if errors.Is(err, ErrNoKey) {
				continue
			}
			if err != nil {
				return shared, fmt.Errorf("%s/%s: %w", p.Slug, e.Slug, err)
			}
			rows, err := wrapAll(device, key, v.recipients(&p, &e))
			key.Wipe()
			if err != nil {
				return shared, err
			}
			if err := c.putWrappedKeys(ctx, e.ID, payload.Epoch, device.DeviceID, rows); err != nil {
				return shared, err
			}
			shared++
		}
	}
	return shared, nil
}

// ---------------------------------------------------------------- projects and environments

func (s *Service) CreateProject(ctx context.Context, org, slug, name string) error {
	_, c, err := s.signedIn()
	if err != nil {
		return err
	}
	return c.createProject(ctx, org, slug, name)
}

// CreateEnvironment creates an environment and its first key, wrapped for
// everyone the chain allows to use it.
func (s *Service) CreateEnvironment(ctx context.Context, org, project, slug string) error {
	st, c, device, err := s.ready()
	if err != nil {
		return err
	}
	if err := c.createEnvironment(ctx, org, project, slug); err != nil {
		return err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return err
	}
	p, e, err := v.environment(project, slug)
	if err != nil {
		return err
	}
	key, err := s.firstKey(ctx, c, st, device, v, p, e)
	if err != nil {
		return err
	}
	key.Wipe()
	return nil
}

// firstKey creates epoch 1's key of an environment that has none and no
// values yet, and shares it.
func (s *Service) firstKey(ctx context.Context, c *Client, st *State, device *cloudcrypto.Device, v *view, p *projectJSON, e *environmentJSON) (*cloudcrypto.EnvironmentKey, error) {
	me, err := v.member(st.UserID)
	if err != nil {
		return nil, err
	}
	if !me.CanAdminister(p.Slug, e.Slug) {
		return nil, ErrNoKey
	}
	key, err := cloudcrypto.NewEnvironmentKey(v.trust.OrgID, p.ID, e.ID, e.Epoch)
	if err != nil {
		return nil, err
	}
	recipients := v.recipients(p, e)
	if !slices.ContainsFunc(recipients, func(r recipient) bool {
		return !r.token && r.cert.RecipientID == device.DeviceID && r.cert.UserID == st.UserID
	}) {
		key.Wipe()
		return nil, fmt.Errorf("this device is missing from %s's certified devices", v.snap.Slug)
	}
	rows, err := wrapAll(device, key, recipients)
	if err == nil {
		err = c.putWrappedKeys(ctx, e.ID, e.Epoch, device.DeviceID, rows)
	}
	if err != nil {
		key.Wipe()
		return nil, err
	}
	return key, nil
}

// Rotate starts the environment's next epoch: a new key for the recipients
// the chain allows now, and every current value encrypted again under it,
// so anyone removed cannot read what is written from now on.
func (s *Service) Rotate(ctx context.Context, org, project, env string) (uint64, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return 0, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return 0, err
	}
	p, e, err := v.environment(project, env)
	if err != nil {
		return 0, err
	}
	me, err := v.member(st.UserID)
	if err != nil {
		return 0, err
	}
	if !me.CanAdminister(project, env) {
		return 0, fmt.Errorf("your role cannot rotate %s/%s", project, env)
	}
	opened, err := s.fetch(ctx, c, st, device, v, p, e, false)
	if err != nil && !errors.Is(err, ErrNoKey) {
		return 0, err
	}
	if opened != nil {
		defer opened.wipe()
	} else if len(e.Secrets) > 0 {
		return 0, err
	}
	epoch := e.Epoch + 1
	if opened != nil {
		epoch = opened.payload.Epoch + 1
	}
	key, err := cloudcrypto.NewEnvironmentKey(v.trust.OrgID, p.ID, e.ID, epoch)
	if err != nil {
		return 0, err
	}
	defer key.Wipe()
	rows, err := wrapAll(device, key, v.recipients(p, e))
	if err != nil {
		return 0, err
	}
	var versions []*cloudcrypto.SecretRecord
	if opened != nil {
		for _, sec := range opened.payload.Secrets {
			record, err := device.Seal(key, sec.Name, sec.Version+1, opened.values[sec.Name])
			if err != nil {
				return 0, err
			}
			versions = append(versions, record)
		}
	}
	if err := c.rotateEnvironment(ctx, e.ID, epoch, device.DeviceID, rows, versions); err != nil {
		return 0, err
	}
	if refreshed, err := s.fetch(ctx, c, st, device, v, p, e, false); err == nil {
		refreshed.wipe()
	}
	return epoch, nil
}

// ---------------------------------------------------------------- machine tokens

// CreateToken creates a machine token for CI on this device, registers its
// public half, and wraps the keys of the environments in scope for it. The
// returned token is shown once; the server never sees its private parts.
func (s *Service) CreateToken(ctx context.Context, org, name string, scope []string, ttl time.Duration) (string, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return "", err
	}
	account, err := st.account()
	if err != nil {
		return "", err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return "", err
	}
	token, err := cloudcrypto.NewMachineToken(v.trust.OrgID, v.trust.Roots)
	if err != nil {
		return "", err
	}
	cert := account.CertifyMachine(token.ID, token.Identity.Recipient().String(), scope)
	if err := c.createToken(ctx, org, name, cert, token.SecretHash(), time.Now().Add(ttl)); err != nil {
		return "", err
	}
	identities := map[string]age.Identity{device.DeviceID: device.Identity}
	for _, p := range v.snap.Projects {
		for _, e := range p.Environments {
			if v.trust.VerifyRecipient(v.certs, cert, p.Slug, e.Slug) != nil {
				continue
			}
			payload, err := c.fetchEnvironment(ctx, e.ID, device.DeviceID)
			if err != nil {
				return "", err
			}
			key, err := v.verifier(&p, &e, payload).key(payload, identities, st.UserID)
			if err != nil {
				return "", fmt.Errorf("%s/%s: %w", p.Slug, e.Slug, err)
			}
			rows, err := wrapAll(device, key, []recipient{{cert: cert, token: true}})
			key.Wipe()
			if err == nil {
				err = c.putWrappedKeys(ctx, e.ID, payload.Epoch, device.DeviceID, rows)
			}
			if err != nil {
				return "", err
			}
		}
	}
	return token.String(), nil
}

// RevokeToken ends a machine token. The server marks what it could read for
// rotation.
func (s *Service) RevokeToken(ctx context.Context, id string) error {
	_, c, err := s.signedIn()
	if err != nil {
		return err
	}
	return c.revokeToken(ctx, id)
}
