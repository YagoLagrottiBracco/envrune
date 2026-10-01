// Package cloud is the EnvRune Cloud client: it talks to the API in
// cloud/web, keeps this device's state in the local vault, and does all
// encryption and verification with internal/cloudcrypto. The server only
// sees what this package sends it. See docs/cloud-crypto.md.
package cloud

import (
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// JSON shapes of the API. Binary fields are base64, which encoding/json
// maps to []byte, and times that signatures cover are microseconds.

type deviceJSON struct {
	UserID       string  `json:"user_id"`
	ID           string  `json:"id"`
	Kind         string  `json:"kind"`
	Name         string  `json:"name"`
	AgeRecipient string  `json:"age_recipient"`
	SigningKey   []byte  `json:"signing_key"`
	CreatedAtUS  int64   `json:"created_at_us"`
	Signature    []byte  `json:"signature"`
	RevokedAt    *string `json:"revoked_at"`
	// The account key encrypted to this device by the one that approved it;
	// sent only to the device's owner.
	AccountKeyWrapped []byte `json:"account_key_wrapped,omitempty"`
}

func (d deviceJSON) certificate() *cloudcrypto.RecipientCertificate {
	return &cloudcrypto.RecipientCertificate{Kind: d.Kind, UserID: d.UserID, RecipientID: d.ID, AgeRecipient: d.AgeRecipient,
		SigningKey: d.SigningKey, CreatedAt: time.UnixMicro(d.CreatedAtUS), Signature: d.Signature}
}

type certJSON struct {
	OrgID      string   `json:"org_id"`
	UserID     string   `json:"user_id"`
	AccountKey []byte   `json:"account_key"`
	Role       string   `json:"role"`
	Scope      []string `json:"scope"`
	IssuedAtUS int64    `json:"issued_at_us"`
	IssuerID   string   `json:"issuer_id"`
	Signature  []byte   `json:"signature"`
}

func (c certJSON) certificate() *cloudcrypto.MembershipCertificate {
	return &cloudcrypto.MembershipCertificate{OrgID: c.OrgID, UserID: c.UserID, AccountKey: c.AccountKey, Role: c.Role, Scope: c.Scope,
		IssuedAt: time.UnixMicro(c.IssuedAtUS), IssuerID: c.IssuerID, Signature: c.Signature}
}

type tokenJSON struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	CreatedBy    string   `json:"created_by"`
	AgeRecipient string   `json:"age_recipient"`
	Scope        []string `json:"scope"`
	CreatedAtUS  int64    `json:"created_at_us"`
	Signature    []byte   `json:"signature"`
	ExpiresAt    string   `json:"expires_at"`
	RevokedAt    *string  `json:"revoked_at"`
}

func (t tokenJSON) certificate() *cloudcrypto.RecipientCertificate {
	return &cloudcrypto.RecipientCertificate{Kind: cloudcrypto.KindMachine, UserID: t.CreatedBy, RecipientID: t.ID, AgeRecipient: t.AgeRecipient,
		Scope: t.Scope, CreatedAt: time.UnixMicro(t.CreatedAtUS), Signature: t.Signature}
}

type secretMeta struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CurrentVersion uint64 `json:"current_version"`
}

type environmentJSON struct {
	ID            string       `json:"id"`
	Slug          string       `json:"slug"`
	Epoch         uint64       `json:"epoch"`
	NeedsRotation bool         `json:"needs_rotation"`
	Secrets       []secretMeta `json:"secrets"`
}

type projectJSON struct {
	ID           string            `json:"id"`
	Slug         string            `json:"slug"`
	Name         string            `json:"name"`
	Environments []environmentJSON `json:"environments"`
}

type accountKeyJSON struct {
	UserID     string `json:"user_id"`
	AccountKey []byte `json:"account_key"`
}

// accountJSON is GET /account: the caller's registration and devices.
type accountJSON struct {
	UserID         string       `json:"user_id"`
	Registered     bool         `json:"registered"`
	AccountKey     []byte       `json:"account_key"`
	RecoveryBackup []byte       `json:"recovery_backup"`
	Devices        []deviceJSON `json:"devices"`
}

// OrgSummary is one entry of GET /orgs.
type OrgSummary struct {
	ID    string   `json:"id"`
	Slug  string   `json:"slug"`
	Name  string   `json:"name"`
	Role  string   `json:"role"`
	Scope []string `json:"scope"`
}

type memberJSON struct {
	UserID string   `json:"user_id"`
	Role   string   `json:"role"`
	Scope  []string `json:"scope"`
}

// Snapshot is GET /orgs/{slug}: everything needed to verify and act.
type Snapshot struct {
	ID           string           `json:"id"`
	Slug         string           `json:"slug"`
	Name         string           `json:"name"`
	OfflineDays  *int             `json:"offline_days"`
	Roots        []accountKeyJSON `json:"roots"`
	Certificates []certJSON       `json:"certificates"`
	Members      []memberJSON     `json:"members"`
	Accounts     []accountKeyJSON `json:"accounts"`
	Devices      []deviceJSON     `json:"devices"`
	Projects     []projectJSON    `json:"projects"`
	Tokens       []tokenJSON      `json:"tokens"`
	Rotation     []rotationJSON   `json:"rotation"`
}

// rotationJSON is a guided rotation: the secrets someone who left could read.
type rotationJSON struct {
	ID            string  `json:"id"`
	Reason        string  `json:"reason"`
	SubjectUserID *string `json:"subject_user_id"`
	SubjectToken  *string `json:"subject_token"`
	CreatedAt     string  `json:"created_at"`
	Items         []struct {
		SecretID string `json:"secret_id"`
		Status   string `json:"status"`
	} `json:"rotation_items"`
}

func (s *Snapshot) environment(project, env string) (*projectJSON, *environmentJSON, bool) {
	for i := range s.Projects {
		p := &s.Projects[i]
		if p.Slug != project {
			continue
		}
		for j := range p.Environments {
			if p.Environments[j].Slug == env {
				return p, &p.Environments[j], true
			}
		}
	}
	return nil, nil, false
}

type wrappedJSON struct {
	Epoch            uint64  `json:"epoch"`
	RecipientUserID  *string `json:"recipient_user_id"`
	RecipientTokenID *string `json:"recipient_token_id"`
	RecipientID      string  `json:"recipient_id"`
	Wrapped          []byte  `json:"wrapped"`
	WrapperUserID    string  `json:"wrapper_user_id"`
	WrapperDeviceID  string  `json:"wrapper_device_id"`
	Signature        []byte  `json:"signature"`
}

type secretJSON struct {
	Name           string `json:"name"`
	Version        uint64 `json:"version"`
	Epoch          uint64 `json:"epoch"`
	Nonce          []byte `json:"nonce"`
	Ciphertext     []byte `json:"ciphertext"`
	WriterUserID   string `json:"writer_user_id"`
	WriterDeviceID string `json:"writer_device_id"`
	Signature      []byte `json:"signature"`
}

// EnvPayload is what fetching an environment returns: ciphertext and keys
// wrapped for the caller, never a value.
type EnvPayload struct {
	EnvironmentID string        `json:"environment_id"`
	Epoch         uint64        `json:"epoch"`
	WrappedKeys   []wrappedJSON `json:"wrapped_keys"`
	Secrets       []secretJSON  `json:"secrets"`
	Devices       []deviceJSON  `json:"devices"`
	// IDs and Certificates let a machine token, which has no snapshot,
	// verify writers and wrappers. Members check them against their pinned
	// roots the same way, so the cache verifies offline.
	IDs struct {
		OrgID     string `json:"org_id"`
		ProjectID string `json:"project_id"`
	} `json:"ids"`
	Certificates []certJSON `json:"certificates"`
}

func (w wrappedJSON) record(orgID, projectID, envID string) *cloudcrypto.WrappedKey {
	user := ""
	if w.RecipientUserID != nil {
		user = *w.RecipientUserID
	}
	return &cloudcrypto.WrappedKey{OrgID: orgID, ProjectID: projectID, EnvironmentID: envID, Epoch: w.Epoch, RecipientUserID: user,
		RecipientID: w.RecipientID, Wrapped: w.Wrapped, WrapperUserID: w.WrapperUserID, WrapperDeviceID: w.WrapperDeviceID, Signature: w.Signature}
}

func (s secretJSON) record(orgID, projectID, envID string) *cloudcrypto.SecretRecord {
	return &cloudcrypto.SecretRecord{OrgID: orgID, ProjectID: projectID, EnvironmentID: envID, Name: s.Name, Version: s.Version, Epoch: s.Epoch,
		Nonce: s.Nonce, Ciphertext: s.Ciphertext, WriterUserID: s.WriterUserID, WriterDeviceID: s.WriterDeviceID, Signature: s.Signature}
}

func wrappedToJSON(w *cloudcrypto.WrappedKey, token bool) map[string]any {
	out := map[string]any{"recipient_id": w.RecipientID, "wrapped": w.Wrapped, "signature": w.Signature}
	if token {
		out["recipient_token_id"] = w.RecipientID
	} else {
		out["recipient_user_id"] = w.RecipientUserID
	}
	return out
}
