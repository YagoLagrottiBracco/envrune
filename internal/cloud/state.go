package cloud

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// State is this device's EnvRune Cloud state. It lives in the local vault,
// encrypted with the vault's data key, like every secret.
type State struct {
	Server string `json:"server"`
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Tokens Tokens `json:"tokens"`

	// AccountSeed is the account's private key; empty on a device that is
	// waiting for approval.
	AccountSeed []byte `json:"account_seed,omitempty"`

	DeviceID          string `json:"device_id,omitempty"`
	DeviceIdentity    string `json:"device_identity,omitempty"` // age identity
	DeviceSigningSeed []byte `json:"device_signing_seed,omitempty"`
	DeviceApproved    bool   `json:"device_approved,omitempty"`

	Orgs map[string]*OrgState `json:"orgs,omitempty"` // by slug

	// Versions is the newest version and epoch seen per secret, so the
	// server cannot serve older ones unnoticed.
	Versions map[string][2]uint64 `json:"versions,omitempty"`

	// Use holds the notes of use this device has not reported yet.
	Use []UseRecord `json:"use,omitempty"`
}

// OrgState is what this device learned about one organization.
type OrgState struct {
	ID string `json:"id"`
	// Roots are pinned the first time this device sees the organization;
	// a server cannot change them afterwards.
	Roots map[string][]byte `json:"roots"`
	// Certificates keeps every membership certificate this device verified,
	// so a removal it has seen cannot be hidden later.
	Certificates []certJSON `json:"certificates,omitempty"`
	// Cache holds the last fetch of each environment, as ciphertext, so
	// commands work offline.
	Cache map[string]*CachedEnv `json:"cache,omitempty"` // "project/env"
	// AuditHead is the newest audit entry this device verified, so a later
	// export must still hold it.
	AuditHead *AuditHead `json:"audit_head,omitempty"`
	// OfflineDays is how long the organization lets a copy in Cache be used
	// without syncing, as last heard from the server; zero means forever.
	OfflineDays int `json:"offline_days,omitempty"`
}

// CachedEnv is one environment as last fetched: ciphertext, keys wrapped
// for this device, and the certificates that verify them, which the
// pinned roots check again on every read.
type CachedEnv struct {
	ProjectID     string      `json:"project_id"`
	EnvironmentID string      `json:"environment_id"`
	Payload       *EnvPayload `json:"payload"`
	FetchedAt     time.Time   `json:"fetched_at"`
}

var ErrNoAccount = errors.New("this device has no EnvRune Cloud account yet; run `envrune cloud init`")

func parseState(raw []byte) (*State, error) {
	s := &State{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, s); err != nil {
			return nil, err
		}
	}
	if s.Orgs == nil {
		s.Orgs = map[string]*OrgState{}
	}
	if s.Versions == nil {
		s.Versions = map[string][2]uint64{}
	}
	return s, nil
}

func (s *State) account() (*cloudcrypto.Account, error) {
	if len(s.AccountSeed) == 0 {
		return nil, ErrNoAccount
	}
	return cloudcrypto.AccountFromSeed(s.UserID, s.AccountSeed)
}

func (s *State) device() (*cloudcrypto.Device, error) {
	if s.DeviceID == "" {
		return nil, ErrNoAccount
	}
	return cloudcrypto.DeviceFromKeys(s.UserID, s.DeviceID, s.DeviceIdentity, s.DeviceSigningSeed)
}

func (s *State) org(slug string) *OrgState {
	o := s.Orgs[slug]
	if o == nil {
		o = &OrgState{Roots: map[string][]byte{}, Cache: map[string]*CachedEnv{}}
		s.Orgs[slug] = o
	}
	if o.Cache == nil {
		o.Cache = map[string]*CachedEnv{}
	}
	return o
}

func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
