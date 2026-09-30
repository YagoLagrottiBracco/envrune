package cloudcrypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
)

// Kinds of recipient certificate.
const (
	KindDevice   = "device"   // a user's device, certified by the user's account key
	KindRecovery = "recovery" // a user's recovery identity, certified by the account key
	KindMachine  = "machine"  // a CI token, certified by an admin's account key
)

// RecipientCertificate says that an age recipient (and, for devices, a
// signing key) belongs to a user, or to a machine token an admin created.
type RecipientCertificate struct {
	Kind         string
	UserID       string // for machines, the admin who created it
	RecipientID  string // device id, "recovery", or machine token id
	AgeRecipient string
	SigningKey   ed25519.PublicKey // devices only
	Scope        []string          // machines only; see Allows
	CreatedAt    time.Time
	Signature    []byte
}

func (c *RecipientCertificate) signed() []byte {
	return message("envrune-recipient-v1", str(c.Kind), str(c.UserID), str(c.RecipientID), str(c.AgeRecipient),
		c.SigningKey, str(strings.Join(c.Scope, "\n")), unix(c.CreatedAt))
}

// CertifyDevice signs a device's public keys with the account key: on the
// device itself after recovery, or on a trusted device approving a new one.
func (a *Account) CertifyDevice(deviceID, ageRecipient string, signingKey ed25519.PublicKey) *RecipientCertificate {
	c := &RecipientCertificate{Kind: KindDevice, UserID: a.UserID, RecipientID: deviceID, AgeRecipient: ageRecipient, SigningKey: signingKey, CreatedAt: time.Now()}
	c.Signature = a.sign(c.signed())
	return c
}

// CertifyRecovery signs the user's recovery recipient, which receives every
// environment key the user gets, so the recovery key restores access.
func (a *Account) CertifyRecovery(ageRecipient string) *RecipientCertificate {
	c := &RecipientCertificate{Kind: KindRecovery, UserID: a.UserID, RecipientID: KindRecovery, AgeRecipient: ageRecipient, CreatedAt: time.Now()}
	c.Signature = a.sign(c.signed())
	return c
}

// CertifyMachine signs a machine token's recipient, limited to scope.
func (a *Account) CertifyMachine(tokenID, ageRecipient string, scope []string) *RecipientCertificate {
	c := &RecipientCertificate{Kind: KindMachine, UserID: a.UserID, RecipientID: tokenID, AgeRecipient: ageRecipient, Scope: scope, CreatedAt: time.Now()}
	c.Signature = a.sign(c.signed())
	return c
}

// Verify checks the certificate against the account key of the user who
// signed it.
func (c *RecipientCertificate) Verify(account ed25519.PublicKey) error {
	return verify(account, c.signed(), c.Signature)
}

// Recipient parses the certified age recipient.
func (c *RecipientCertificate) Recipient() (*age.X25519Recipient, error) {
	return age.ParseX25519Recipient(c.AgeRecipient)
}

// Roles, from most to least powerful. Removed marks a membership that ended.
const (
	RoleOwner      = "owner"
	RoleAdmin      = "admin"
	RoleMaintainer = "maintainer"
	RoleConsumer   = "consumer"
	RoleAuditor    = "auditor"
	RoleRemoved    = "removed"
)

var roles = []string{RoleOwner, RoleAdmin, RoleMaintainer, RoleConsumer, RoleAuditor, RoleRemoved}

// MembershipCertificate says that a user, with a given account key, has a
// role in an organization, limited to a scope. It is signed by an owner or an
// admin whose own membership chains to the organization's root.
type MembershipCertificate struct {
	OrgID      string
	UserID     string
	AccountKey ed25519.PublicKey
	Role       string
	Scope      []string // "project/environment", "project/*", or "*"
	IssuedAt   time.Time
	IssuerID   string
	Signature  []byte
}

func (c *MembershipCertificate) signed() []byte {
	return message("envrune-member-v1", str(c.OrgID), str(c.UserID), c.AccountKey, str(c.Role),
		str(strings.Join(c.Scope, "\n")), unix(c.IssuedAt), str(c.IssuerID))
}

// Certify signs a membership as this account. Whether this account may
// issue it is decided when the chain is verified.
func (a *Account) Certify(orgID, userID string, accountKey ed25519.PublicKey, role string, scope []string) (*MembershipCertificate, error) {
	if !slices.Contains(roles, role) {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	c := &MembershipCertificate{OrgID: orgID, UserID: userID, AccountKey: accountKey, Role: role, Scope: scope, IssuedAt: time.Now(), IssuerID: a.UserID}
	c.Signature = a.sign(c.signed())
	return c, nil
}

// Allows reports whether scope covers an environment of a project.
func Allows(scope []string, project, environment string) bool {
	for _, s := range scope {
		if s == "*" || s == project+"/*" || s == project+"/"+environment {
			return true
		}
	}
	return false
}

// Membership is a verified member.
type Membership struct {
	UserID     string
	AccountKey ed25519.PublicKey
	Role       string
	Scope      []string
	Root       bool // one of the pinned root holders
}

// CanUse reports whether the member receives the environment key.
func (m Membership) CanUse(project, environment string) bool {
	switch m.Role {
	case RoleOwner, RoleAdmin, RoleMaintainer, RoleConsumer:
		return m.Root || Allows(m.Scope, project, environment)
	}
	return false
}

// CanAdminister reports whether the member may write values to an
// environment and wrap its key for others.
func (m Membership) CanAdminister(project, environment string) bool {
	switch m.Role {
	case RoleOwner, RoleAdmin, RoleMaintainer:
		return m.Root || Allows(m.Scope, project, environment)
	}
	return false
}

// Trust verifies memberships of one organization against the root account
// keys every member pinned when joining.
type Trust struct {
	OrgID string
	Roots map[string]ed25519.PublicKey // user id → account key
}

var errNoMembership = errors.New("no valid membership")

// Verify returns the current membership of userID, reached through a chain
// of certificates that ends at a root. certs is everything the server
// returned; the server can hide certificates but not forge them. For each
// user the newest valid certificate wins, so a removal takes effect.
func (t Trust) Verify(certs []*MembershipCertificate, userID string) (Membership, error) {
	return t.verify(certs, userID, map[string]bool{})
}

func (t Trust) verify(certs []*MembershipCertificate, userID string, visiting map[string]bool) (Membership, error) {
	if root, ok := t.Roots[userID]; ok {
		return Membership{UserID: userID, AccountKey: root, Role: RoleOwner, Scope: []string{"*"}, Root: true}, nil
	}
	if visiting[userID] {
		return Membership{}, ErrUntrusted
	}
	visiting[userID] = true
	defer delete(visiting, userID)

	var best *MembershipCertificate
	for _, c := range certs {
		if c.OrgID != t.OrgID || c.UserID != userID || (best != nil && !c.IssuedAt.After(best.IssuedAt)) {
			continue
		}
		issuer, err := t.verify(certs, c.IssuerID, visiting)
		if err != nil || verify(issuer.AccountKey, c.signed(), c.Signature) != nil || !mayIssue(issuer, c) {
			continue
		}
		best = c
	}
	if best == nil {
		return Membership{}, ErrUntrusted
	}
	if best.Role == RoleRemoved {
		return Membership{}, errNoMembership
	}
	return Membership{UserID: userID, AccountKey: best.AccountKey, Role: best.Role, Scope: best.Scope}, nil
}

// mayIssue: owners issue anything; admins issue anything but owner, never
// about an owner, and only within their own scope.
func mayIssue(issuer Membership, c *MembershipCertificate) bool {
	switch issuer.Role {
	case RoleOwner:
		return true
	case RoleAdmin:
		if c.Role == RoleOwner {
			return false
		}
		for _, s := range c.Scope {
			if !scopeCovers(issuer.Scope, s) {
				return false
			}
		}
		return true
	}
	return false
}

// scopeCovers reports whether scope includes the whole of entry.
func scopeCovers(scope []string, entry string) bool {
	for _, s := range scope {
		if s == "*" || s == entry {
			return true
		}
		if project, ok := strings.CutSuffix(s, "/*"); ok && strings.HasPrefix(entry, project+"/") {
			return true
		}
	}
	return false
}

// VerifyRecipient checks that a recipient certificate belongs to a verified
// member (devices and recovery) or was created by one who may administer the
// environment (machines), and that it may receive this environment's key.
func (t Trust) VerifyRecipient(certs []*MembershipCertificate, c *RecipientCertificate, project, environment string) error {
	member, err := t.Verify(certs, c.UserID)
	if err != nil {
		return err
	}
	if err := c.Verify(member.AccountKey); err != nil {
		return err
	}
	switch c.Kind {
	case KindDevice, KindRecovery:
		if !member.CanUse(project, environment) {
			return fmt.Errorf("%s may not use %s/%s: %w", c.UserID, project, environment, ErrUntrusted)
		}
	case KindMachine:
		if !member.CanAdminister(project, environment) || !Allows(c.Scope, project, environment) {
			return fmt.Errorf("machine %s may not use %s/%s: %w", c.RecipientID, project, environment, ErrUntrusted)
		}
	default:
		return ErrMalformed
	}
	return nil
}
