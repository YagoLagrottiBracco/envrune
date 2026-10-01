package cloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
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

// Handover is what a membership change did besides signing it. Readers
// only accept keys and values signed by someone who may write to the
// environment now, so when a member loses that, everything they signed is
// signed again by whoever made the change.
type Handover struct {
	// Shared counts the environments whose keys were shared with the
	// member's devices (adding or changing a member).
	Shared int
	// Rotated lists the environments, as project/env, given a new epoch.
	Rotated []string
	// Left lists the environments the member signed for or could read that
	// this account does not administer: until someone who does rotates
	// them with acceptRemoved, their values do not verify.
	Left []string
	// Reissued lists the members whose membership the changed member had
	// signed, and this account signed again.
	Reissued []string
	// Orphaned lists the members whose membership the changed member had
	// signed and this account may not sign: an owner must add them again.
	Orphaned []string
	// Revoked lists the machine tokens a removed member had created, and so
	// had seen.
	Revoked []string
}

// AddMember signs a membership for an account whose fingerprint the admin
// confirmed, then shares with the member's devices the environment keys
// this device holds and may share.
func (s *Service) AddMember(ctx context.Context, org string, account *Account, role string, scope []string) (*Handover, error) {
	if role == cloudcrypto.RoleRemoved {
		return nil, errors.New("use RemoveMember")
	}
	return s.certify(ctx, org, account.UserID, account.Key, role, scope)
}

// ChangeMember signs a new role or scope for a current member, whose key
// comes from their verified membership rather than from the server.
func (s *Service) ChangeMember(ctx context.Context, org, userID, role string, scope []string) (*Handover, error) {
	if role == cloudcrypto.RoleRemoved {
		return nil, errors.New("use RemoveMember")
	}
	current, err := s.verifiedMember(ctx, org, userID)
	if err != nil {
		return nil, err
	}
	return s.certify(ctx, org, userID, current.AccountKey, role, scope)
}

// RemoveMember signs a removal and rotates every environment the member
// could use and this device administers, so they cannot read anything
// written afterwards. The values they already knew still need replacing
// (`envrune cloud rotation`).
func (s *Service) RemoveMember(ctx context.Context, org, userID string) (*Handover, error) {
	st, err := s.state()
	if err != nil {
		return nil, err
	}
	if userID == st.UserID {
		return nil, errors.New("you cannot remove yourself; ask another owner or admin")
	}
	removed, err := s.verifiedMember(ctx, org, userID)
	if err != nil {
		return nil, err
	}
	return s.certify(ctx, org, userID, removed.AccountKey, cloudcrypto.RoleRemoved, nil)
}

func (s *Service) verifiedMember(ctx context.Context, org, userID string) (cloudcrypto.Membership, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return cloudcrypto.Membership{}, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return cloudcrypto.Membership{}, err
	}
	member, err := v.trust.Verify(v.certs, userID)
	if err != nil {
		return member, fmt.Errorf("%s is not a verified member: %w", userID, err)
	}
	return member, nil
}

// certify signs a membership and hands over what the member signed and can
// no longer answer for. The order matters: the environments are opened
// while the member's signatures still verify, then the change is signed,
// then each environment gets a new epoch signed by this device. Nothing
// along the way relies on a signature from someone who already left.
func (s *Service) certify(ctx context.Context, org, userID string, key ed25519.PublicKey, role string, scope []string) (*Handover, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return nil, err
	}
	account, err := st.account()
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
	removal := role == cloudcrypto.RoleRemoved
	after := cloudcrypto.Membership{UserID: userID, AccountKey: key, Role: role, Scope: scope}
	h := &Handover{}

	type pending struct {
		project, env string
		current      *opened
	}
	var rotate []pending
	defer func() {
		for _, r := range rotate {
			if r.current != nil {
				r.current.wipe()
			}
		}
	}()
	if before, err := v.trust.Verify(v.certs, userID); err == nil && !before.Root {
		for _, p := range v.snap.Projects {
			for _, e := range p.Environments {
				if !(removal && before.CanUse(p.Slug, e.Slug)) && !(before.CanAdminister(p.Slug, e.Slug) && !after.CanAdminister(p.Slug, e.Slug)) {
					continue
				}
				if !me.CanAdminister(p.Slug, e.Slug) {
					h.Left = append(h.Left, p.Slug+"/"+e.Slug)
					continue
				}
				current, err := s.openCurrent(ctx, c, st, device, v, &p, &e, false)
				if err != nil && !(errors.Is(err, ErrNoKey) && len(e.Secrets) == 0) {
					return h, fmt.Errorf("%s/%s: %w", p.Slug, e.Slug, err)
				}
				rotate = append(rotate, pending{project: p.Slug, env: e.Slug, current: current})
			}
		}
		// Memberships the member signed stop verifying once they may not
		// sign them: sign again the ones this account may.
		for _, m := range v.snap.Members {
			held, err := v.trust.Verify(v.certs, m.UserID)
			if err != nil || m.UserID == userID || held.IssuerID != userID || after.MayIssue(held.Role, held.Scope) {
				continue
			}
			if !me.MayIssue(held.Role, held.Scope) {
				h.Orphaned = append(h.Orphaned, m.UserID)
				continue
			}
			again, err := account.Certify(v.trust.OrgID, m.UserID, held.AccountKey, held.Role, held.Scope)
			if err != nil {
				return h, err
			}
			if err := c.addMembership(ctx, org, again); err != nil {
				return h, fmt.Errorf("signing %s's membership again: %w", m.UserID, err)
			}
			h.Reissued = append(h.Reissued, m.UserID)
		}
	}

	cert, err := account.Certify(v.trust.OrgID, userID, key, role, scope)
	if err != nil {
		return h, err
	}
	if err := c.addMembership(ctx, org, cert); err != nil {
		return h, err
	}
	if removal {
		// They created these tokens, so they saw them.
		for _, t := range v.snap.Tokens {
			if t.CreatedBy == userID && t.RevokedAt == nil {
				if err := c.revokeToken(ctx, t.ID); err != nil {
					return h, fmt.Errorf("revoking token %s: %w", t.ID, err)
				}
				h.Revoked = append(h.Revoked, t.ID)
			}
		}
	}

	if len(rotate) > 0 {
		if v, err = s.view(ctx, c, org); err != nil {
			return h, err
		}
		for _, r := range rotate {
			p, e, err := v.environment(r.project, r.env)
			if err != nil {
				return h, err
			}
			if _, err := s.rotateTo(ctx, c, st, device, v, p, e, r.current); err != nil {
				return h, fmt.Errorf("%s/%s: %w", r.project, r.env, err)
			}
			h.Rotated = append(h.Rotated, r.project+"/"+r.env)
		}
	}
	if !removal {
		if h.Shared, err = s.shareAll(ctx, c, st, device, org); err != nil {
			return h, err
		}
	}
	return h, nil
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
// the chain allows now, and every current value encrypted again under it
// and signed by this device, so anyone removed cannot read what is written
// from now on.
//
// acceptRemoved also accepts a key or a value signed by a member who could
// write to the environment once and cannot now, which readers refuse. It is
// for environments a removal left behind. Use it knowing that the device
// cannot tell what such a member signed before leaving from what was signed
// with their key afterwards.
func (s *Service) Rotate(ctx context.Context, org, project, env string, acceptRemoved bool) (uint64, error) {
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
	current, err := s.openCurrent(ctx, c, st, device, v, p, e, acceptRemoved)
	if err != nil && !(errors.Is(err, ErrNoKey) && len(e.Secrets) == 0) {
		return 0, err
	}
	if current != nil {
		defer current.wipe()
	}
	return s.rotateTo(ctx, c, st, device, v, p, e, current)
}

// openCurrent fetches, verifies, and decrypts an environment to rotate it,
// without storing it as the offline cache.
func (s *Service) openCurrent(ctx context.Context, c *Client, st *State, device *cloudcrypto.Device, v *view, p *projectJSON, e *environmentJSON, former bool) (*opened, error) {
	payload, err := c.fetchEnvironment(ctx, e.ID, device.DeviceID)
	if err != nil {
		return nil, err
	}
	ver := v.verifier(p, e, payload)
	ver.former = former
	key, err := ver.key(payload, map[string]age.Identity{device.DeviceID: device.Identity}, st.UserID)
	if err != nil {
		return nil, err
	}
	values, err := ver.open(payload, key, maps.Clone(st.Versions), false)
	if err != nil {
		key.Wipe()
		return nil, err
	}
	return &opened{payload: payload, key: key, values: values}, nil
}

// rotateTo starts the epoch after current, which is nil for an environment
// with no key and no values yet. v decides who receives the new key.
func (s *Service) rotateTo(ctx context.Context, c *Client, st *State, device *cloudcrypto.Device, v *view, p *projectJSON, e *environmentJSON, current *opened) (uint64, error) {
	epoch := e.Epoch + 1
	if current != nil {
		epoch = current.payload.Epoch + 1
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
	if current != nil {
		for _, sec := range current.payload.Secrets {
			record, err := device.Seal(key, sec.Name, sec.Version+1, current.values[sec.Name])
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
