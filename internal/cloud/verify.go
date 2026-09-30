package cloud

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

var (
	ErrNoKey = errors.New("no key for this environment reached this device yet; ask an administrator to run `envrune cloud share`")
	// ErrOrgChanged means the server answered with another organization
	// than the one this device pinned under that name.
	ErrOrgChanged = errors.New("the server returned a different organization than the one this device pinned; refusing to trust it")
)

// verifier checks one environment's wrapped keys and values against the
// pinned roots. Everything it trusts is reached through signatures: device
// certificates signed by account keys, account keys in membership
// certificates, and those chained to a root.
type verifier struct {
	orgID, projectID, envID string
	project, env            string // slugs, which roles and scopes name
	trust                   cloudcrypto.Trust
	certs                   []*cloudcrypto.MembershipCertificate
	devices                 []deviceJSON
}

func certificates(certs ...[]certJSON) []*cloudcrypto.MembershipCertificate {
	var out []*cloudcrypto.MembershipCertificate
	for _, list := range certs {
		for _, c := range list {
			out = append(out, c.certificate())
		}
	}
	return out
}

func pinned(roots map[string][]byte) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(roots))
	for user, key := range roots {
		out[user] = key
	}
	return out
}

// signer returns the signing key of a device of userID, after checking its
// certificate against the user's verified membership and that allowed
// accepts that membership.
func (v *verifier) signer(userID, deviceID string, allowed func(cloudcrypto.Membership) bool) (ed25519.PublicKey, error) {
	member, err := v.trust.Verify(v.certs, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", userID, err)
	}
	if !allowed(member) {
		return nil, fmt.Errorf("%s may not sign for %s/%s: %w", userID, v.project, v.env, cloudcrypto.ErrUntrusted)
	}
	for _, d := range v.devices {
		if d.UserID != userID || d.ID != deviceID || d.Kind != cloudcrypto.KindDevice {
			continue
		}
		cert := d.certificate()
		if err := cert.Verify(member.AccountKey); err != nil || len(cert.SigningKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("device %s of %s: %w", deviceID, userID, cloudcrypto.ErrUntrusted)
		}
		return cert.SigningKey, nil
	}
	return nil, fmt.Errorf("device %s of %s is unknown: %w", deviceID, userID, cloudcrypto.ErrUntrusted)
}

// key unwraps the environment key of the payload's epoch with one of
// identities, keyed by recipient id. A wrapper must administer the
// environment, or be the recipient user sharing with their own device.
func (v *verifier) key(payload *EnvPayload, identities map[string]age.Identity, recipientUser string) (*cloudcrypto.EnvironmentKey, error) {
	var failure error
	for _, w := range payload.WrappedKeys {
		identity, ok := identities[w.RecipientID]
		if !ok || w.Epoch != payload.Epoch {
			continue
		}
		record := w.record(v.orgID, v.projectID, v.envID)
		if record.RecipientUserID != recipientUser {
			continue
		}
		wrapper, err := v.signer(w.WrapperUserID, w.WrapperDeviceID, func(m cloudcrypto.Membership) bool {
			return m.CanAdminister(v.project, v.env) || (recipientUser != "" && w.WrapperUserID == recipientUser && m.CanUse(v.project, v.env))
		})
		if err == nil {
			var key *cloudcrypto.EnvironmentKey
			if key, err = cloudcrypto.Unwrap(record, identity, wrapper); err == nil {
				return key, nil
			}
		}
		failure = err
	}
	if failure != nil {
		return nil, failure
	}
	return nil, ErrNoKey
}

// open decrypts every value of the payload, checks each writer, and refuses
// a version or epoch older than one in seen, unless allowOlder. seen is
// updated; nil skips the check.
func (v *verifier) open(payload *EnvPayload, key *cloudcrypto.EnvironmentKey, seen map[string][2]uint64, allowOlder bool) (map[string][]byte, error) {
	values := make(map[string][]byte, len(payload.Secrets))
	fail := func(err error) (map[string][]byte, error) {
		wipeValues(values)
		return nil, err
	}
	for _, s := range payload.Secrets {
		record := s.record(v.orgID, v.projectID, v.envID)
		id := versionKey(v.orgID, v.projectID, v.envID, s.Name)
		if last, ok := seen[id]; ok && !allowOlder && (record.Version < last[0] || record.Epoch < last[1]) {
			return fail(fmt.Errorf("%w: %s version %d, epoch %d; this device saw version %d, epoch %d (use --allow-older to accept it)",
				cloudcrypto.ErrRollback, s.Name, record.Version, record.Epoch, last[0], last[1]))
		}
		writer, err := v.signer(s.WriterUserID, s.WriterDeviceID, func(m cloudcrypto.Membership) bool { return m.CanAdminister(v.project, v.env) })
		if err != nil {
			return fail(fmt.Errorf("%s: %w", s.Name, err))
		}
		value, err := cloudcrypto.Open(record, key, writer)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", s.Name, err))
		}
		values[s.Name] = value
		if seen != nil {
			last := seen[id]
			seen[id] = [2]uint64{max(last[0], record.Version), max(last[1], record.Epoch)}
		}
	}
	return values, nil
}

func versionKey(orgID, projectID, envID, name string) string {
	return orgID + "/" + projectID + "/" + envID + "/" + name
}

func wipeValues(values map[string][]byte) {
	for _, v := range values {
		wipe(v)
	}
	clear(values)
}
