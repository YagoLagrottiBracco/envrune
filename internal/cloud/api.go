package cloud

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// One method per /api/v1 route the CLI uses.

func (c *Client) account(ctx context.Context) (*accountJSON, error) {
	var out accountJSON
	return &out, c.call(ctx, http.MethodGet, "/account", nil, nil, &out)
}

func (c *Client) registerAccount(ctx context.Context, public, backup []byte, recovery *cloudcrypto.RecipientCertificate) error {
	return c.call(ctx, http.MethodPost, "/account", nil, map[string]any{
		"account_key":     public,
		"recovery_backup": backup,
		"recovery": map[string]any{
			"age_recipient": recovery.AgeRecipient,
			"created_at_us": recovery.CreatedAt.UnixMicro(),
			"signature":     recovery.Signature,
		},
	}, nil)
}

// resetRecovery replaces the account's recovery backup and recovery
// recipient, from the approved device deviceID.
func (c *Client) resetRecovery(ctx context.Context, deviceID string, backup []byte, recovery *cloudcrypto.RecipientCertificate) error {
	return c.call(ctx, http.MethodPost, "/account/recovery", nil, map[string]any{
		"device_id":       deviceID,
		"recovery_backup": backup,
		"recovery": map[string]any{
			"age_recipient": recovery.AgeRecipient,
			"created_at_us": recovery.CreatedAt.UnixMicro(),
			"signature":     recovery.Signature,
		},
	}, nil)
}

// registerDevice uploads a device's public keys; cert.Signature is nil for a
// device waiting for approval.
func (c *Client) registerDevice(ctx context.Context, name string, cert *cloudcrypto.RecipientCertificate) error {
	in := map[string]any{
		"id":            cert.RecipientID,
		"name":          name,
		"age_recipient": cert.AgeRecipient,
		"signing_key":   []byte(cert.SigningKey),
		"created_at_us": cert.CreatedAt.UnixMicro(),
	}
	if cert.Signature != nil {
		in["signature"] = cert.Signature
	}
	return c.call(ctx, http.MethodPost, "/devices", nil, in, nil)
}

func (c *Client) approveDevice(ctx context.Context, cert *cloudcrypto.RecipientCertificate, accountKeyWrapped []byte) error {
	return c.call(ctx, http.MethodPost, "/devices/"+url.PathEscape(cert.RecipientID)+"/approve", nil, map[string]any{
		"created_at_us":       cert.CreatedAt.UnixMicro(),
		"signature":           cert.Signature,
		"account_key_wrapped": accountKeyWrapped,
	}, nil)
}

func (c *Client) revokeDevice(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/devices/"+url.PathEscape(id), nil, nil, nil)
}

func (c *Client) orgs(ctx context.Context) ([]OrgSummary, error) {
	var out []OrgSummary
	return out, c.call(ctx, http.MethodGet, "/orgs", nil, nil, &out)
}

func (c *Client) createOrg(ctx context.Context, slug, name string, roots []string) error {
	return c.call(ctx, http.MethodPost, "/orgs", nil, map[string]any{"slug": slug, "name": name, "roots": nonNil(roots)}, nil)
}

func (c *Client) snapshot(ctx context.Context, slug string) (*Snapshot, error) {
	var out Snapshot
	return &out, c.call(ctx, http.MethodGet, "/orgs/"+url.PathEscape(slug), nil, nil, &out)
}

// setOfflineDays sets the organization's offline limit; zero turns it off.
func (c *Client) setOfflineDays(ctx context.Context, slug string, days int) error {
	var value any
	if days > 0 {
		value = days
	}
	return c.call(ctx, http.MethodPatch, "/orgs/"+url.PathEscape(slug), nil, map[string]any{"offline_days": value}, nil)
}

func (c *Client) lookupAccount(ctx context.Context, email string) (*accountKeyJSON, error) {
	var out accountKeyJSON
	return &out, c.call(ctx, http.MethodGet, "/accounts", url.Values{"email": {email}}, nil, &out)
}

func (c *Client) addMembership(ctx context.Context, slug string, cert *cloudcrypto.MembershipCertificate) error {
	return c.call(ctx, http.MethodPost, "/orgs/"+url.PathEscape(slug)+"/members", nil, map[string]any{
		"user_id":      cert.UserID,
		"role":         cert.Role,
		"scope":        nonNil(cert.Scope),
		"issued_at_us": cert.IssuedAt.UnixMicro(),
		"signature":    cert.Signature,
	}, nil)
}

func (c *Client) createProject(ctx context.Context, org, slug, name string) error {
	return c.call(ctx, http.MethodPost, "/orgs/"+url.PathEscape(org)+"/projects", nil, map[string]string{"slug": slug, "name": name}, nil)
}

func (c *Client) createEnvironment(ctx context.Context, org, project, slug string) error {
	path := "/orgs/" + url.PathEscape(org) + "/projects/" + url.PathEscape(project) + "/environments"
	return c.call(ctx, http.MethodPost, path, nil, map[string]string{"slug": slug}, nil)
}

func (c *Client) fetchEnvironment(ctx context.Context, envID, deviceID string) (*EnvPayload, error) {
	var out EnvPayload
	return &out, c.call(ctx, http.MethodGet, "/environments/"+url.PathEscape(envID), url.Values{"device": {deviceID}}, nil, &out)
}

func (c *Client) putWrappedKeys(ctx context.Context, envID string, epoch uint64, deviceID string, keys []map[string]any) error {
	for len(keys) > 0 {
		batch := keys[:min(len(keys), 500)]
		keys = keys[len(batch):]
		err := c.call(ctx, http.MethodPut, "/environments/"+url.PathEscape(envID)+"/keys", nil, map[string]any{
			"epoch": epoch, "device": deviceID, "keys": batch,
		}, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) putSecretVersion(ctx context.Context, envID string, r *cloudcrypto.SecretRecord) error {
	return c.call(ctx, http.MethodPost, "/environments/"+url.PathEscape(envID)+"/secrets", nil, map[string]any{
		"name": r.Name, "version": r.Version, "epoch": r.Epoch, "nonce": r.Nonce, "ciphertext": r.Ciphertext,
		"device": r.WriterDeviceID, "signature": r.Signature,
	}, nil)
}

func (c *Client) rotateEnvironment(ctx context.Context, envID string, epoch uint64, deviceID string, keys []map[string]any, versions []*cloudcrypto.SecretRecord) error {
	rows := make([]map[string]any, 0, len(versions))
	for _, r := range versions {
		rows = append(rows, map[string]any{"name": r.Name, "version": r.Version, "nonce": r.Nonce, "ciphertext": r.Ciphertext, "signature": r.Signature})
	}
	return c.call(ctx, http.MethodPost, "/environments/"+url.PathEscape(envID)+"/rotate", nil, map[string]any{
		"new_epoch": epoch, "device": deviceID, "keys": keys, "versions": rows,
	}, nil)
}

func (c *Client) createToken(ctx context.Context, org, name string, cert *cloudcrypto.RecipientCertificate, secretHash []byte, expires time.Time) error {
	return c.call(ctx, http.MethodPost, "/orgs/"+url.PathEscape(org)+"/tokens", nil, map[string]any{
		"id": cert.RecipientID, "name": name, "age_recipient": cert.AgeRecipient, "scope": nonNil(cert.Scope),
		"created_at_us": cert.CreatedAt.UnixMicro(), "signature": cert.Signature, "secret_hash": secretHash,
		"expires_at": expires.UTC().Format(time.RFC3339),
	}, nil)
}

func (c *Client) revokeToken(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/tokens/"+url.PathEscape(id), nil, nil, nil)
}

func (c *Client) updateRotationItem(ctx context.Context, task, secret, status string) error {
	path := "/rotation/" + url.PathEscape(task) + "/items/" + url.PathEscape(secret)
	return c.call(ctx, http.MethodPatch, path, nil, map[string]string{"status": status}, nil)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
