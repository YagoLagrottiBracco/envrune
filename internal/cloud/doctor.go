package cloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// Database states a server reports about itself in /health.
const (
	DatabaseOK          = "ok"
	DatabaseBehind      = "behind"
	DatabaseAhead       = "ahead"
	DatabaseUnreachable = "unreachable"
)

// ServerHealth is what a server says about itself before anyone signs in.
type ServerHealth struct {
	// Database is whether the server's database has the schema the server
	// needs; empty when the server is too old to say.
	Database string
}

// CheckLevel says how bad a Check is.
type CheckLevel int

const (
	CheckOK CheckLevel = iota
	CheckWarn
	CheckFail
)

// Check is one line of `envrune cloud doctor`. Messages hold names and
// fingerprints, never a value or a key.
type Check struct {
	Level   CheckLevel
	Message string
}

// Health asks the server this vault is signed in to about itself.
func (s *Service) Health(ctx context.Context) (*ServerHealth, error) {
	st, err := s.state()
	if err != nil {
		return nil, err
	}
	if st.Server == "" {
		return nil, ErrSignedOut
	}
	return (&Client{Server: st.Server, HTTP: s.HTTP}).Health(ctx)
}

// Doctor checks, in the order a new user meets them, what has to hold for
// EnvRune Cloud to work from this device: the server answers and its
// database has its schema, the session is valid, this device is trusted,
// the recovery recipient is the account's, and each organization verifies.
// It stops at the first thing the rest depends on.
func (s *Service) Doctor(ctx context.Context) []Check {
	var out []Check
	add := func(level CheckLevel, format string, args ...any) {
		out = append(out, Check{level, fmt.Sprintf(format, args...)})
	}
	st, err := s.state()
	if err != nil {
		add(CheckFail, "the vault's EnvRune Cloud state cannot be read: %v", err)
		return out
	}
	if st.Server == "" {
		add(CheckFail, "not signed in; run `envrune login`")
		return out
	}
	health, err := (&Client{Server: st.Server, HTTP: s.HTTP}).Health(ctx)
	if err != nil {
		add(CheckFail, "server %s: %v", st.Server, err)
		return out
	}
	add(CheckOK, "server: %s answers", st.Server)
	switch health.Database {
	case DatabaseOK:
		add(CheckOK, "the server's database has the schema the server needs")
	case DatabaseBehind:
		add(CheckFail, "the server's database is behind the server; whoever runs it applies the files in cloud/supabase/migrations")
	case DatabaseAhead:
		add(CheckWarn, "the server's database is newer than the server; whoever runs it deploys the newer server")
	case DatabaseUnreachable:
		add(CheckFail, "the server cannot reach its database")
	default:
		add(CheckWarn, "the server is too old to say whether its database is up to date")
	}

	_, c, err := s.signedIn()
	if err != nil {
		add(CheckFail, "%v", err)
		return out
	}
	remote, err := c.account(ctx)
	if err != nil {
		add(CheckFail, "session: %v", err)
		return out
	}
	add(CheckOK, "signed in as %s", st.Email)
	if !remote.Registered {
		add(CheckWarn, "this account has no keys yet; run `envrune cloud init`")
		return out
	}

	trusted := false
	registered := findDevice(remote.Devices, st.DeviceID)
	switch {
	case st.DeviceID == "" || registered == nil:
		add(CheckWarn, "this device is not set up; run `envrune cloud init`")
	case registered.RevokedAt != nil:
		add(CheckFail, "this device was revoked; set it up again with a new vault")
	case registered.Signature == nil || !st.DeviceApproved || len(st.AccountSeed) == 0:
		add(CheckWarn, "this device is waiting for approval; run `envrune cloud device approve %s` on a trusted device, then `envrune cloud init` here", st.DeviceID)
	default:
		account, err := st.account()
		switch {
		case err != nil:
			add(CheckFail, "this device's account key cannot be read: %v", err)
		case !account.Public.Equal(ed25519.PublicKey(remote.AccountKey)):
			add(CheckFail, "this device's account key is not the one the server has registered")
		case registered.certificate().Verify(account.Public) != nil:
			add(CheckFail, "this device's certificate on the server is not signed by your account key")
		default:
			trusted = true
			add(CheckOK, "this device is trusted; account fingerprint %s", cloudcrypto.Fingerprint(account.Public))
		}
	}

	recovery := recoveryRecipient(remote.Devices)
	switch {
	case recovery == nil:
		add(CheckFail, "the server has no recovery recipient for this account; run `envrune cloud recovery reset`")
	case recovery.certificate().Verify(ed25519.PublicKey(remote.AccountKey)) != nil:
		add(CheckFail, "the server's recovery recipient is not signed by your account key; run `envrune cloud recovery reset`")
	default:
		add(CheckOK, "the recovery key's recipient on the server is signed by your account key")
	}
	if !trusted {
		return out
	}

	orgs, err := c.orgs(ctx)
	if err != nil {
		add(CheckFail, "organizations: %v", err)
		return out
	}
	for _, o := range orgs {
		v, err := s.view(ctx, c, o.Slug)
		if err != nil {
			add(CheckFail, "organization %s: %v", o.Slug, err)
			continue
		}
		me, err := v.trust.Verify(v.certs, st.UserID)
		if err != nil {
			add(CheckFail, "organization %s: your membership does not verify: %v", o.Slug, err)
			continue
		}
		add(CheckOK, "organization %s: you are %s, and the membership verifies against the roots this device pinned", o.Slug, me.Role)
		for _, p := range v.snap.Projects {
			for _, e := range p.Environments {
				if e.NeedsRotation && me.CanAdminister(p.Slug, e.Slug) {
					add(CheckWarn, "environment %s/%s/%s waits for a new key; run `envrune cloud rotate %s/%s/%s`", o.Slug, p.Slug, e.Slug, o.Slug, p.Slug, e.Slug)
				}
			}
		}
	}
	return out
}

func recoveryRecipient(devices []deviceJSON) *deviceJSON {
	for i := range devices {
		if devices[i].Kind == cloudcrypto.KindRecovery && bytes.Equal([]byte(devices[i].ID), []byte(cloudcrypto.KindRecovery)) {
			return &devices[i]
		}
	}
	return nil
}
