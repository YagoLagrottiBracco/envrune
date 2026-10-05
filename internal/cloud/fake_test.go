package cloud

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// fakeServer plays the EnvRune Cloud API in memory with the permission
// rules of the database functions: roles and scopes, the next version, the
// current epoch. It stores what clients send and checks no signature, as a
// compromised server would not; tests change its fields to attack clients.
type fakeServer struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	emails   map[string]string // email → user id
	profiles map[string]*fakeProfile
	devices  []*deviceJSON
	orgs     []*fakeOrg
	certs    []certJSON
	members  map[string]map[string]memberJSON // org id → user id
	projects []*fakeProject
	envs     []*fakeEnv
	versions map[string][]secretJSON // env id → every version, all secrets
	wrapped  []*fakeWrapped
	// database is what /health says about the schema.
	database string
	tokens   []*fakeToken
	fetches  int
	checks   int
	// expired holds Authorization values the server answers 401 to once,
	// as it does when a session ran out.
	expired map[string]bool
	// written is when the current version of each secret was stored,
	// transition until when its previous value should work, and lastFetch
	// when each reader last fetched each environment.
	// proxy is the server's proxy identity, and sensitive what was sealed
	// to it, by secret id.
	proxy     *age.X25519Identity
	sensitive map[string]*fakeSensitive
	// grants are the requests for access for a limited time, by organization.
	grants []*fakeGrant
	// upstream plays the services that forwarded requests go to, and
	// forwarded counts them by "user device secret host".
	upstream   http.Handler
	forwarded  map[string]int
	written    map[string]time.Time
	transition map[string]time.Time
	lastFetch  map[string]map[fakeReader]time.Time
	// unreachable makes version checks answer too slowly to wait for.
	unreachable bool
	// fetched records who fetched each environment, as the audit log does:
	// env id → "user:<id>" or "token:<id>". Guided rotation starts from it.
	fetched   map[string]map[string]bool
	rotations []*fakeRotation
	audits    map[string][]AuditEntry // org id → its chain
	// injectRoot is a root of its own that a lying server adds to every
	// organization founded.
	injectRoot *accountKeyJSON
	auditID    int64
}

type fakeProfile struct{ key, backup []byte }

type fakeOrg struct {
	id, slug, name string
	roots          []accountKeyJSON
	offlineDays    *int
	policy         []PolicyRule
}

type fakeProject struct{ id, org, slug, name string }

type fakeEnv struct {
	id, project, slug string
	epoch             uint64
	needsRotation     bool
}

type fakeWrapped struct {
	env string
	w   wrappedJSON
}

// fakeSensitive is a sensitive secret's current version: what members are
// shown, and the ciphertext only the server keeps.
type fakeSensitive struct {
	json   sensitiveJSON
	sealed []byte
}

// fakeGrant is a request for access and what became of it.
type fakeGrant struct {
	AccessGrant
	org       string
	decidedAt time.Time
}

// fakeReader is a member's device, or a machine token.
type fakeReader struct{ user, device, token string }

type fakeRotation struct {
	rotationJSON
	org string
}

type fakeToken struct {
	json   tokenJSON
	org    string
	hash   []byte
	expiry time.Time
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, emails: map[string]string{}, profiles: map[string]*fakeProfile{}, members: map[string]map[string]memberJSON{},
		versions: map[string][]secretJSON{}, fetched: map[string]map[string]bool{},
		audits: map[string][]AuditEntry{}, written: map[string]time.Time{}, transition: map[string]time.Time{},
		lastFetch: map[string]map[fakeReader]time.Time{}, sensitive: map[string]*fakeSensitive{}, database: DatabaseOK}
	f.proxy, _ = age.GenerateX25519Identity()
	mux := http.NewServeMux()
	route := func(pattern string, h func(user string, r *http.Request) (any, int, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			user := ""
			if !strings.Contains(pattern, "/health") && !strings.Contains(pattern, "/machine/") && !strings.HasSuffix(pattern, "/v1/proxy") {
				claims, err := parseClaims(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
				if err != nil {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign in"})
					return
				}
				user = claims.Subject
			}
			out, status, err := h(user, r)
			if err != nil {
				writeJSON(w, status, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, status, out)
		})
	}
	route("GET /api/v1/health", func(string, *http.Request) (any, int, error) {
		return map[string]any{"service": "envrune-cloud", "api": 1, "database": f.database}, 200, nil
	})
	route("GET /api/v1/account", f.getAccount)
	route("POST /api/v1/account", f.postAccount)
	route("POST /api/v1/account/recovery", f.postRecovery)
	route("POST /api/v1/account/reset", f.postAccountReset)
	route("GET /api/v1/accounts", f.getAccounts)
	route("POST /api/v1/devices", f.postDevice)
	route("POST /api/v1/devices/{id}/approve", f.approveDevice)
	route("DELETE /api/v1/devices/{id}", f.revokeDevice)
	route("GET /api/v1/orgs", f.getOrgs)
	route("POST /api/v1/orgs", f.postOrg)
	route("GET /api/v1/orgs/{org}", f.getOrg)
	route("PATCH /api/v1/orgs/{org}", f.patchOrg)
	route("PUT /api/v1/orgs/{org}/policy", f.putPolicy)
	route("GET /api/v1/orgs/{org}/access", f.getAccess)
	route("POST /api/v1/orgs/{org}/access", f.postAccess)
	route("POST /api/v1/access/{id}", f.decideAccess)
	route("POST /api/v1/orgs/{org}/members", f.postMember)
	route("POST /api/v1/orgs/{org}/projects", f.postProject)
	route("POST /api/v1/orgs/{org}/projects/{project}/environments", f.postEnvironment)
	route("POST /api/v1/orgs/{org}/tokens", f.postToken)
	route("POST /api/v1/orgs/{org}/projects/{project}/emergency", f.postEmergency)
	route("DELETE /api/v1/tokens/{id}", f.deleteToken)
	route("GET /api/v1/environments/{env}", f.getEnvironment)
	route("PUT /api/v1/environments/{env}/keys", f.putKeys)
	route("POST /api/v1/environments/{env}/secrets", f.postSecret)
	route("POST /api/v1/environments/{env}/rotate", f.postRotate)
	route("GET /api/v1/machine/environment", f.machineEnvironment)
	route("PATCH /api/v1/rotation/{task}/items/{secret}", f.patchRotationItem)
	route("GET /api/v1/orgs/{org}/audit", f.getAudit)
	route("GET /api/v1/versions", f.getVersions)
	route("GET /api/v1/proxy", f.getProxy)
	route("POST /api/v1/environments/{env}/sensitive", f.postSensitive)
	route("GET /api/v1/environments/{env}/status", f.getStatus)
	route("POST /api/v1/environments/{env}/use", f.postUse)
	route("PUT /api/v1/environments/{env}/secrets/{name}/transition", f.putTransition)
	mux.HandleFunc("/api/v1/forward", f.forward)
	f.forwarded = map[string]int{}
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != http.StatusNoContent {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func decode[T any](r *http.Request) T {
	var v T
	_ = json.NewDecoder(r.Body).Decode(&v)
	return v
}

var (
	errForbidden = fmt.Errorf("not allowed")
	errNotFound  = fmt.Errorf("not found")
	errConflict  = fmt.Errorf("stale; sync and retry")
)

func fail(status int, err error) (any, int, error) { return nil, status, err }

// ---------------------------------------------------------------- rules

func (f *fakeServer) role(org, user string) memberJSON { return f.members[org][user] }

func (f *fakeServer) envInfo(id string) (*fakeEnv, *fakeProject) {
	for _, e := range f.envs {
		if e.id == id {
			for _, p := range f.projects {
				if p.id == e.project {
					return e, p
				}
			}
		}
	}
	return nil, nil
}

func (f *fakeServer) canUse(env, user string) bool {
	e, p := f.envInfo(env)
	m := f.role(p.org, user)
	return e != nil && slices.Contains([]string{"owner", "admin", "maintainer", "consumer"}, m.Role) && cloudcrypto.Allows(m.Scope, p.slug, e.slug) &&
		!f.policyDenies(p.org, m.Role, p.slug, e.slug) && !f.grantExpired(p.org, user, p.slug, e.slug)
}

// grantExpired reports that the member's hold on the environment came from
// a grant whose time is up.
func (f *fakeServer) grantExpired(org, user, project, env string) bool {
	return slices.ContainsFunc(f.grants, func(g *fakeGrant) bool {
		return g.org == org && g.UserID == user && g.Status == "approved" && !time.Now().Before(*g.ExpiresAt) &&
			cloudcrypto.Allows(g.Scope, project, env) && !cloudcrypto.Allows(g.BaseScope, project, env)
	})
}

func (f *fakeServer) getAccess(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	if o == nil {
		return fail(404, errNotFound)
	}
	out := []AccessGrant{}
	for i := len(f.grants) - 1; i >= 0; i-- {
		if g := f.grants[i]; g.org == o.id && (g.UserID == user || f.isAdmin(o.id, user)) {
			out = append(out, g.AccessGrant)
		}
	}
	return out, 200, nil
}

func (f *fakeServer) postAccess(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct {
		Scope   []string `json:"scope"`
		Minutes int      `json:"minutes"`
		Reason  string   `json:"reason"`
	}](r)
	if o == nil || f.role(o.id, user).Role == "auditor" {
		return fail(403, errForbidden)
	}
	if len(b.Scope) == 0 || b.Minutes < 5 || b.Minutes > 10080 {
		return fail(400, fmt.Errorf("invalid request"))
	}
	if slices.ContainsFunc(f.grants, func(g *fakeGrant) bool { return g.org == o.id && g.UserID == user && g.Status == "pending" }) {
		return fail(409, fmt.Errorf("you already have a request waiting"))
	}
	g := &fakeGrant{org: o.id, AccessGrant: AccessGrant{ID: fmt.Sprintf("grant-%d", len(f.grants)+1), UserID: user, Scope: b.Scope,
		Minutes: b.Minutes, Reason: b.Reason, Status: "pending", RequestedAt: time.Now()}}
	f.grants = append(f.grants, g)
	f.audit(o.id, user, "access.request", user, `{}`)
	return map[string]string{"id": g.ID}, 201, nil
}

func (f *fakeServer) decideAccess(user string, r *http.Request) (any, int, error) {
	b := decode[struct {
		Decision  string   `json:"decision"`
		BaseScope []string `json:"base_scope"`
	}](r)
	for _, g := range f.grants {
		if g.ID != r.PathValue("id") {
			continue
		}
		if !f.isAdmin(g.org, user) {
			return fail(403, errForbidden)
		}
		switch b.Decision {
		case "deny":
			if g.Status != "pending" {
				return fail(404, errNotFound)
			}
			g.Status = "denied"
			return nil, 204, nil
		case "approve":
			held := f.role(g.org, g.UserID).Scope
			covers := func(all, part []string) bool {
				return !slices.ContainsFunc(part, func(x string) bool { return !slices.Contains(all, x) })
			}
			if g.Status != "pending" {
				return fail(404, errNotFound)
			}
			if !covers(held, g.Scope) || !covers(held, b.BaseScope) || !covers(append(slices.Clone(b.BaseScope), g.Scope...), held) {
				return fail(400, fmt.Errorf("the signed scope is not the scope before plus what was asked"))
			}
			until := time.Now().Add(time.Duration(g.Minutes) * time.Minute)
			g.Status, g.ExpiresAt, g.BaseScope, g.decidedAt = "approved", &until, b.BaseScope, time.Now()
			if g.BaseScope == nil {
				g.BaseScope = []string{}
			}
			f.audit(g.org, user, "access.approve", g.UserID, `{}`)
			return map[string]any{"expires_at": until}, 200, nil
		case "close":
			if g.Status != "ended" || g.ListedAt != nil {
				return nil, 204, nil
			}
			listed := time.Now()
			g.ListedAt = &listed
			task := &fakeRotation{org: g.org, rotationJSON: rotationJSON{ID: fmt.Sprintf("rot-%d", len(f.rotations)+1), Reason: "access ended",
				SubjectUserID: &g.UserID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
			for _, e := range f.envs {
				_, p := f.envInfo(e.id)
				at, fetched := f.lastFetchBy(e.id, g.UserID)
				if p.org != g.org || !cloudcrypto.Allows(g.Scope, p.slug, e.slug) || cloudcrypto.Allows(g.BaseScope, p.slug, e.slug) || !fetched || at.Before(g.decidedAt) {
					continue
				}
				for _, sec := range f.current(e.id) {
					task.Items = append(task.Items, struct {
						SecretID string `json:"secret_id"`
						Status   string `json:"status"`
					}{secretID(e.id, sec.Name), RotationPending})
				}
			}
			if len(task.Items) > 0 {
				f.rotations = append(f.rotations, task)
			}
			f.audit(g.org, user, "access.end", g.UserID, `{}`)
			return nil, 204, nil
		}
		return fail(400, fmt.Errorf("unknown decision"))
	}
	return fail(404, errNotFound)
}

// lastFetchBy is when any device of user last fetched the environment.
func (f *fakeServer) lastFetchBy(env, user string) (time.Time, bool) {
	var last time.Time
	for reader, at := range f.lastFetch[env] {
		if reader.user == user && at.After(last) {
			last = at
		}
	}
	return last, !last.IsZero()
}

func (f *fakeServer) canAdminister(env, user string) bool {
	e, p := f.envInfo(env)
	m := f.role(p.org, user)
	return e != nil && slices.Contains([]string{"owner", "admin", "maintainer"}, m.Role) && cloudcrypto.Allows(m.Scope, p.slug, e.slug) &&
		!f.policyDenies(p.org, m.Role, p.slug, e.slug) && !f.grantExpired(p.org, user, p.slug, e.slug)
}

// policyDenies applies the organization's rules, which never touch owners.
func (f *fakeServer) policyDenies(org, role, project, env string) bool {
	if role == "owner" {
		return false
	}
	for _, o := range f.orgs {
		if o.id == org {
			return slices.ContainsFunc(o.policy, func(r PolicyRule) bool { return r.matches(project, env) && slices.Contains(r.Deny, role) })
		}
	}
	return false
}

func (f *fakeServer) putPolicy(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct {
		Rules []PolicyRule `json:"rules"`
	}](r)
	if o == nil || f.role(o.id, user).Role != "owner" {
		return fail(403, errForbidden)
	}
	if err := CheckPolicy(b.Rules); err != nil {
		return fail(400, err)
	}
	o.policy = b.Rules
	f.audit(o.id, user, "policy.set", "", `{}`)
	return nil, 204, nil
}

func (f *fakeServer) isAdmin(org, user string) bool {
	return slices.Contains([]string{"owner", "admin"}, f.role(org, user).Role)
}

func (f *fakeServer) orgBySlug(slug, user string) *fakeOrg {
	for _, o := range f.orgs {
		if o.slug == slug && f.role(o.id, user).Role != "" && f.role(o.id, user).Role != "removed" {
			return o
		}
	}
	return nil
}

func (f *fakeServer) device(user, id string) *deviceJSON {
	for _, d := range f.devices {
		if d.UserID == user && d.ID == id {
			return d
		}
	}
	return nil
}

// ---------------------------------------------------------------- accounts and devices

func (f *fakeServer) getAccount(user string, _ *http.Request) (any, int, error) {
	out := accountJSON{UserID: user}
	if p := f.profiles[user]; p != nil {
		out.Registered, out.AccountKey, out.RecoveryBackup = true, p.key, p.backup
	}
	for _, d := range f.devices {
		if d.UserID == user {
			out.Devices = append(out.Devices, *d)
		}
	}
	return out, 200, nil
}

func (f *fakeServer) postAccount(user string, r *http.Request) (any, int, error) {
	b := decode[struct {
		AccountKey     []byte `json:"account_key"`
		RecoveryBackup []byte `json:"recovery_backup"`
		Recovery       struct {
			AgeRecipient string `json:"age_recipient"`
			CreatedAtUS  int64  `json:"created_at_us"`
			Signature    []byte `json:"signature"`
		} `json:"recovery"`
	}](r)
	if f.profiles[user] != nil {
		return fail(409, fmt.Errorf("already registered"))
	}
	f.profiles[user] = &fakeProfile{key: b.AccountKey, backup: b.RecoveryBackup}
	f.devices = append(f.devices, &deviceJSON{UserID: user, ID: "recovery", Kind: "recovery", Name: "recovery key",
		AgeRecipient: b.Recovery.AgeRecipient, CreatedAtUS: b.Recovery.CreatedAtUS, Signature: b.Recovery.Signature})
	return map[string]string{"user_id": user}, 201, nil
}

// postRecovery replaces the backup and the recovery recipient, and drops
// what was wrapped for the old one, as reset_recovery does.
func (f *fakeServer) postRecovery(user string, r *http.Request) (any, int, error) {
	b := decode[struct {
		DeviceID       string `json:"device_id"`
		RecoveryBackup []byte `json:"recovery_backup"`
		Recovery       struct {
			AgeRecipient string `json:"age_recipient"`
			CreatedAtUS  int64  `json:"created_at_us"`
			Signature    []byte `json:"signature"`
		} `json:"recovery"`
	}](r)
	profile := f.profiles[user]
	if profile == nil {
		return fail(404, errNotFound)
	}
	if d := f.device(user, b.DeviceID); d == nil || d.Signature == nil || d.RevokedAt != nil {
		return fail(403, fmt.Errorf("only one of your approved devices replaces the recovery key"))
	}
	cert := &cloudcrypto.RecipientCertificate{Kind: cloudcrypto.KindRecovery, UserID: user, RecipientID: cloudcrypto.KindRecovery,
		AgeRecipient: b.Recovery.AgeRecipient, CreatedAt: time.UnixMicro(b.Recovery.CreatedAtUS), Signature: b.Recovery.Signature}
	if cert.Verify(profile.key) != nil {
		return fail(400, fmt.Errorf("the recovery recipient is not signed by the account key"))
	}
	profile.backup = b.RecoveryBackup
	for _, d := range f.devices {
		if d.UserID == user && d.Kind == cloudcrypto.KindRecovery {
			d.AgeRecipient, d.CreatedAtUS, d.Signature = b.Recovery.AgeRecipient, b.Recovery.CreatedAtUS, b.Recovery.Signature
		}
	}
	f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
		return w.w.RecipientUserID != nil && *w.w.RecipientUserID == user && w.w.RecipientID == cloudcrypto.KindRecovery
	})
	return nil, 204, nil
}

// postAccountReset replaces an account's key, as reset_account does: only
// for an account in no organization that is no root holder, with a device
// and a recovery recipient the new key signed.
func (f *fakeServer) postAccountReset(user string, r *http.Request) (any, int, error) {
	b := decode[struct {
		AccountKey     []byte `json:"account_key"`
		RecoveryBackup []byte `json:"recovery_backup"`
		Recovery       struct {
			AgeRecipient string `json:"age_recipient"`
			CreatedAtUS  int64  `json:"created_at_us"`
			Signature    []byte `json:"signature"`
		} `json:"recovery"`
		Device deviceJSON `json:"device"`
	}](r)
	profile := f.profiles[user]
	if profile == nil {
		return fail(404, errNotFound)
	}
	for _, o := range f.orgs {
		for _, root := range o.roots {
			if root.UserID == user {
				return fail(403, fmt.Errorf("a root holder's account key is pinned by every member of the organization and cannot be replaced"))
			}
		}
		if m := f.role(o.id, user); m.Role != "" && m.Role != "removed" {
			return fail(403, fmt.Errorf("an account is reset only while it is in no organization; ask an owner or admin of each to remove you first"))
		}
	}
	recovery := &cloudcrypto.RecipientCertificate{Kind: cloudcrypto.KindRecovery, UserID: user, RecipientID: cloudcrypto.KindRecovery,
		AgeRecipient: b.Recovery.AgeRecipient, CreatedAt: time.UnixMicro(b.Recovery.CreatedAtUS), Signature: b.Recovery.Signature}
	b.Device.UserID, b.Device.Kind = user, cloudcrypto.KindDevice
	if recovery.Verify(b.AccountKey) != nil || b.Device.certificate().Verify(b.AccountKey) != nil {
		return fail(400, fmt.Errorf("the recovery recipient and the device must be signed by the new account key"))
	}
	profile.key, profile.backup = b.AccountKey, b.RecoveryBackup
	now := time.Now().String()
	for _, d := range f.devices {
		if d.UserID != user {
			continue
		}
		if d.Kind == cloudcrypto.KindRecovery {
			d.AgeRecipient, d.CreatedAtUS, d.Signature = b.Recovery.AgeRecipient, b.Recovery.CreatedAtUS, b.Recovery.Signature
		} else if d.RevokedAt == nil {
			d.RevokedAt = &now
		}
	}
	f.devices = append(f.devices, &deviceJSON{UserID: user, ID: b.Device.ID, Kind: cloudcrypto.KindDevice, Name: b.Device.Name,
		AgeRecipient: b.Device.AgeRecipient, SigningKey: b.Device.SigningKey, CreatedAtUS: b.Device.CreatedAtUS, Signature: b.Device.Signature})
	f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
		return w.w.RecipientUserID != nil && *w.w.RecipientUserID == user
	})
	return nil, 204, nil
}

func (f *fakeServer) getAccounts(_ string, r *http.Request) (any, int, error) {
	user := f.emails[r.URL.Query().Get("email")]
	if f.profiles[user] == nil {
		return fail(404, errNotFound)
	}
	return map[string]string{"user_id": user, "account_key": base64.StdEncoding.EncodeToString(f.profiles[user].key)}, 200, nil
}

func (f *fakeServer) postDevice(user string, r *http.Request) (any, int, error) {
	b := decode[deviceJSON](r)
	if f.device(user, b.ID) != nil {
		return fail(409, fmt.Errorf("exists"))
	}
	f.devices = append(f.devices, &deviceJSON{UserID: user, ID: b.ID, Kind: "device", Name: b.Name, AgeRecipient: b.AgeRecipient,
		SigningKey: b.SigningKey, CreatedAtUS: b.CreatedAtUS, Signature: b.Signature})
	return map[string]any{"id": b.ID}, 201, nil
}

func (f *fakeServer) approveDevice(user string, r *http.Request) (any, int, error) {
	b := decode[struct {
		CreatedAtUS       int64  `json:"created_at_us"`
		Signature         []byte `json:"signature"`
		AccountKeyWrapped []byte `json:"account_key_wrapped"`
	}](r)
	d := f.device(user, r.PathValue("id"))
	if d == nil || d.Signature != nil || d.RevokedAt != nil {
		return fail(404, errNotFound)
	}
	d.CreatedAtUS, d.Signature, d.AccountKeyWrapped = b.CreatedAtUS, b.Signature, b.AccountKeyWrapped
	return map[string]any{"approved": true}, 200, nil
}

func (f *fakeServer) revokeDevice(user string, r *http.Request) (any, int, error) {
	d := f.device(user, r.PathValue("id"))
	if d == nil || d.RevokedAt != nil {
		return fail(404, errNotFound)
	}
	now := time.Now().String()
	d.RevokedAt = &now
	for _, w := range f.wrapped {
		if w.w.RecipientUserID != nil && *w.w.RecipientUserID == user && w.w.RecipientID == d.ID {
			if e, _ := f.envInfo(w.env); e != nil {
				e.needsRotation = true
			}
		}
	}
	f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
		return w.w.RecipientUserID != nil && *w.w.RecipientUserID == user && w.w.RecipientID == d.ID
	})
	// What the device fetched waits for new values, in each organization.
	for _, o := range f.orgs {
		if m := f.role(o.id, user); m.Role != "" && m.Role != "removed" {
			f.startRotation(o.id, "device revoked", &user, nil, &d.ID)
		}
	}
	return nil, 204, nil
}

// ---------------------------------------------------------------- organizations

func (f *fakeServer) getOrgs(user string, _ *http.Request) (any, int, error) {
	out := []OrgSummary{}
	for _, o := range f.orgs {
		if m := f.role(o.id, user); m.Role != "" && m.Role != "removed" {
			out = append(out, OrgSummary{ID: o.id, Slug: o.slug, Name: o.name, Role: m.Role, Scope: m.Scope})
		}
	}
	return out, 200, nil
}

func (f *fakeServer) postOrg(user string, r *http.Request) (any, int, error) {
	b := decode[struct {
		Slug, Name string
		Roots      []string
	}](r)
	if f.profiles[user] == nil {
		return fail(404, errNotFound)
	}
	if len(b.Roots) > 2 {
		return fail(400, fmt.Errorf("an organization has at most two more root holders"))
	}
	o := &fakeOrg{id: "org-" + b.Slug, slug: b.Slug, name: b.Name}
	f.members[o.id] = map[string]memberJSON{}
	for _, holder := range append([]string{user}, b.Roots...) {
		if f.profiles[holder] == nil {
			return fail(404, errNotFound)
		}
		if _, dup := f.members[o.id][holder]; dup {
			return fail(409, fmt.Errorf("exists"))
		}
		o.roots = append(o.roots, accountKeyJSON{UserID: holder, AccountKey: f.profiles[holder].key})
		f.members[o.id][holder] = memberJSON{UserID: holder, Role: "owner", Scope: []string{"*"}}
	}
	if f.injectRoot != nil {
		o.roots = append(o.roots, *f.injectRoot)
	}
	f.orgs = append(f.orgs, o)
	f.audit(o.id, user, "org.create", o.slug, `{}`)
	return map[string]string{"id": o.id}, 201, nil
}

func (f *fakeServer) getOrg(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	if o == nil {
		return fail(404, errNotFound)
	}
	snap := Snapshot{ID: o.id, Slug: o.slug, Name: o.name, Roots: o.roots, OfflineDays: o.offlineDays, Policy: o.policy}
	for _, c := range f.certs {
		if c.OrgID == o.id {
			snap.Certificates = append(snap.Certificates, c)
		}
	}
	for _, m := range f.members[o.id] {
		snap.Members = append(snap.Members, m)
		if p := f.profiles[m.UserID]; p != nil {
			snap.Accounts = append(snap.Accounts, accountKeyJSON{UserID: m.UserID, AccountKey: p.key})
		}
		for _, d := range f.devices {
			if d.UserID == m.UserID && d.Signature != nil && d.RevokedAt == nil {
				public := *d
				public.AccountKeyWrapped = nil
				snap.Devices = append(snap.Devices, public)
			}
		}
	}
	for _, p := range f.projects {
		if p.org != o.id {
			continue
		}
		pj := projectJSON{ID: p.id, Slug: p.slug, Name: p.name}
		for _, e := range f.envs {
			if e.project == p.id {
				pj.Environments = append(pj.Environments, environmentJSON{ID: e.id, Slug: e.slug, Epoch: e.epoch, NeedsRotation: e.needsRotation, Secrets: f.secretMeta(e.id)})
			}
		}
		snap.Projects = append(snap.Projects, pj)
	}
	if f.isAdmin(o.id, user) {
		for _, t := range f.tokens {
			if t.org == o.id {
				snap.Tokens = append(snap.Tokens, t.json)
			}
		}
	}
	for _, r := range f.rotations {
		if r.org == o.id {
			snap.Rotation = append(snap.Rotation, r.rotationJSON)
		}
	}
	for _, sec := range f.sensitive {
		if _, p := f.envInfo(sec.json.EnvironmentID); p != nil && p.org == o.id {
			snap.Sensitive = append(snap.Sensitive, sec.json)
		}
	}
	for _, g := range f.grants {
		if g.org == o.id && g.Status == "approved" && !time.Now().Before(*g.ExpiresAt) {
			snap.Expired = append(snap.Expired, expiredJSON{UserID: g.UserID, Scope: g.Scope, BaseScope: g.BaseScope})
		}
	}
	return snap, 200, nil
}

func (f *fakeServer) patchOrg(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct {
		OfflineDays *int `json:"offline_days"`
	}](r)
	if o == nil || !f.isAdmin(o.id, user) {
		return fail(403, errForbidden)
	}
	if b.OfflineDays != nil && (*b.OfflineDays < 1 || *b.OfflineDays > 365) {
		return fail(400, fmt.Errorf("the offline limit is 1 to 365 days, or none"))
	}
	o.offlineDays = b.OfflineDays
	return nil, 204, nil
}

func secretID(env, name string) string { return "sec-" + env + "-" + name }

func (f *fakeServer) secretMeta(env string) []secretMeta {
	var out []secretMeta
	for _, s := range f.current(env) {
		out = append(out, secretMeta{ID: secretID(env, s.Name), Name: s.Name, CurrentVersion: s.Version})
	}
	return out
}

// current is the newest version of each secret, by name.
func (f *fakeServer) current(env string) []secretJSON {
	newest := map[string]secretJSON{}
	for _, s := range f.versions[env] {
		if s.Version > newest[s.Name].Version {
			newest[s.Name] = s
		}
	}
	var out []secretJSON
	for _, s := range newest {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b secretJSON) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (f *fakeServer) postMember(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct {
		UserID     string   `json:"user_id"`
		Role       string   `json:"role"`
		Scope      []string `json:"scope"`
		IssuedAtUS int64    `json:"issued_at_us"`
		Signature  []byte   `json:"signature"`
	}](r)
	if o == nil || !f.isAdmin(o.id, user) {
		return fail(403, errForbidden)
	}
	if f.profiles[b.UserID] == nil {
		return fail(404, errNotFound)
	}
	if slices.ContainsFunc(o.roots, func(r accountKeyJSON) bool { return r.UserID == b.UserID }) {
		return fail(403, fmt.Errorf("root holders cannot be changed"))
	}
	f.certs = append(f.certs, certJSON{OrgID: o.id, UserID: b.UserID, AccountKey: f.profiles[b.UserID].key, Role: b.Role, Scope: b.Scope,
		IssuedAtUS: b.IssuedAtUS, IssuerID: user, Signature: b.Signature})
	f.members[o.id][b.UserID] = memberJSON{UserID: b.UserID, Role: b.Role, Scope: b.Scope}
	// A later certificate is an administrator's decision about the member's
	// scope, and ends the grants approved before it.
	for _, g := range f.grants {
		if g.org == o.id && g.UserID == b.UserID && g.Status == "approved" {
			g.Status = "ended"
		}
	}
	scope, _ := json.Marshal(nonNil(b.Scope))
	f.audit(o.id, user, "member."+b.Role, b.UserID, `{"scope": `+string(scope)+`}`)
	if b.Role == "removed" {
		f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
			_, p := f.envInfo(w.env)
			return p.org == o.id && w.w.RecipientUserID != nil && *w.w.RecipientUserID == b.UserID
		})
		f.startRotation(o.id, "member removed", &b.UserID, nil)
	}
	return map[string]string{"user_id": b.UserID}, 201, nil
}

func (f *fakeServer) postProject(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct{ Slug, Name string }](r)
	if o == nil || !f.isAdmin(o.id, user) {
		return fail(403, errForbidden)
	}
	p := &fakeProject{id: "prj-" + b.Slug, org: o.id, slug: b.Slug, name: b.Name}
	f.projects = append(f.projects, p)
	return map[string]string{"id": p.id}, 201, nil
}

func (f *fakeServer) postEnvironment(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct{ Slug string }](r)
	if o == nil || !f.isAdmin(o.id, user) {
		return fail(403, errForbidden)
	}
	for _, p := range f.projects {
		if p.org == o.id && p.slug == r.PathValue("project") {
			e := &fakeEnv{id: "env-" + p.slug + "-" + b.Slug, project: p.id, slug: b.Slug, epoch: 1}
			f.envs = append(f.envs, e)
			return map[string]string{"id": e.id}, 201, nil
		}
	}
	return fail(404, errNotFound)
}

// ---------------------------------------------------------------- keys and values

func (f *fakeServer) payload(env string, wrapped func(wrappedJSON) bool) *EnvPayload {
	e, p := f.envInfo(env)
	out := &EnvPayload{EnvironmentID: env, Epoch: e.epoch, Secrets: f.current(env), WrappedKeys: []wrappedJSON{}}
	out.IDs.OrgID, out.IDs.ProjectID = p.org, p.id
	for _, w := range f.wrapped {
		if w.env == env && w.w.Epoch == e.epoch && wrapped(w.w) {
			out.WrappedKeys = append(out.WrappedKeys, w.w)
		}
	}
	for _, d := range f.devices {
		if d.Signature != nil && d.Kind == "device" {
			public := *d
			public.AccountKeyWrapped = nil
			out.Devices = append(out.Devices, public)
		}
	}
	for _, c := range f.certs {
		if c.OrgID == p.org {
			out.Certificates = append(out.Certificates, c)
		}
	}
	return out
}

func (f *fakeServer) getEnvironment(user string, r *http.Request) (any, int, error) {
	env, device := r.PathValue("env"), r.URL.Query().Get("device")
	if e, _ := f.envInfo(env); e == nil || !f.canUse(env, user) {
		return fail(403, errForbidden)
	}
	if d := f.device(user, device); d == nil || d.Signature == nil || d.RevokedAt != nil {
		return fail(403, fmt.Errorf("this device is not approved"))
	}
	f.fetches++
	f.recordFetch(env, "user:"+user)
	f.recordFetch(env, "device:"+user+":"+device)
	f.read(env, fakeReader{user: user, device: device})
	if e, p := f.envInfo(env); e != nil {
		f.audit(p.org, user, "environment.fetch", p.slug+"/"+e.slug, fmt.Sprintf(`{"epoch": %d}`, e.epoch))
	}
	return f.payload(env, func(w wrappedJSON) bool {
		return w.RecipientUserID != nil && *w.RecipientUserID == user && (w.RecipientID == device || w.RecipientID == "recovery")
	}), 200, nil
}

type fakeKeys struct {
	Epoch  uint64 `json:"epoch"`
	Device string `json:"device"`
	Keys   []struct {
		RecipientUserID  *string `json:"recipient_user_id"`
		RecipientTokenID *string `json:"recipient_token_id"`
		RecipientID      string  `json:"recipient_id"`
		Wrapped          []byte  `json:"wrapped"`
		Signature        []byte  `json:"signature"`
	} `json:"keys"`
}

func (f *fakeServer) storeKeys(user, env string, b fakeKeys) (int, error) {
	e, p := f.envInfo(env)
	if e == nil {
		return 404, errNotFound
	}
	admin := f.canAdminister(env, user)
	if !admin && !f.canUse(env, user) {
		return 403, errForbidden
	}
	if b.Epoch != e.epoch {
		return 409, errConflict
	}
	for _, k := range b.Keys {
		if !admin && (k.RecipientUserID == nil || *k.RecipientUserID != user) {
			return 403, fmt.Errorf("only administrators share keys with others")
		}
		if k.RecipientUserID != nil && !f.canUse(env, *k.RecipientUserID) {
			return 403, fmt.Errorf("that member cannot use this environment")
		}
		if k.RecipientTokenID != nil && !slices.ContainsFunc(f.tokens, func(t *fakeToken) bool {
			return t.json.ID == *k.RecipientTokenID && t.org == p.org && cloudcrypto.Allows(t.json.Scope, p.slug, e.slug)
		}) {
			return 403, fmt.Errorf("that token cannot use this environment")
		}
		row := wrappedJSON{Epoch: b.Epoch, RecipientUserID: k.RecipientUserID, RecipientTokenID: k.RecipientTokenID, RecipientID: k.RecipientID,
			Wrapped: k.Wrapped, WrapperUserID: user, WrapperDeviceID: b.Device, Signature: k.Signature}
		f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
			return w.env == env && w.w.Epoch == b.Epoch && w.w.RecipientID == k.RecipientID &&
				(w.w.RecipientUserID == nil) == (k.RecipientUserID == nil) && (k.RecipientUserID == nil || *w.w.RecipientUserID == *k.RecipientUserID)
		})
		f.wrapped = append(f.wrapped, &fakeWrapped{env: env, w: row})
	}
	return 204, nil
}

func (f *fakeServer) putKeys(user string, r *http.Request) (any, int, error) {
	status, err := f.storeKeys(user, r.PathValue("env"), decode[fakeKeys](r))
	return nil, status, err
}

type fakeVersion struct {
	Name       string `json:"name"`
	Version    uint64 `json:"version"`
	Epoch      uint64 `json:"epoch"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Device     string `json:"device"`
	Signature  []byte `json:"signature"`
}

// storeVersion stores the next version of a secret. newValue is false when a
// new epoch encrypts the same value again, which rotates nothing.
func (f *fakeServer) storeVersion(user, env string, b fakeVersion, newValue bool) (int, error) {
	e, _ := f.envInfo(env)
	if e == nil || !f.canAdminister(env, user) {
		return 403, errForbidden
	}
	if b.Epoch != e.epoch {
		return 409, errConflict
	}
	if f.sensitive[secretID(env, b.Name)] != nil {
		return 409, fmt.Errorf("%s is a sensitive secret; set it with --sensitive", b.Name)
	}
	var current uint64
	for _, s := range f.current(env) {
		if s.Name == b.Name {
			current = s.Version
		}
	}
	if b.Version != current+1 {
		return 409, errConflict
	}
	f.versions[env] = append(f.versions[env], secretJSON{Name: b.Name, Version: b.Version, Epoch: b.Epoch, Nonce: b.Nonce, Ciphertext: b.Ciphertext,
		WriterUserID: user, WriterDeviceID: b.Device, Signature: b.Signature})
	f.written[secretID(env, b.Name)] = time.Now()
	delete(f.transition, secretID(env, b.Name))
	if newValue {
		for _, r := range f.rotations {
			for i := range r.Items {
				if r.Items[i].SecretID == secretID(env, b.Name) && r.Items[i].Status == RotationPending {
					r.Items[i].Status = RotationRotated
				}
			}
		}
	}
	return 201, nil
}

func (f *fakeServer) postSecret(user string, r *http.Request) (any, int, error) {
	status, err := f.storeVersion(user, r.PathValue("env"), decode[fakeVersion](r), true)
	return map[string]any{}, status, err
}

func (f *fakeServer) postRotate(user string, r *http.Request) (any, int, error) {
	env := r.PathValue("env")
	b := decode[struct {
		NewEpoch uint64          `json:"new_epoch"`
		Device   string          `json:"device"`
		Keys     json.RawMessage `json:"keys"`
		Versions []fakeVersion   `json:"versions"`
	}](r)
	e, _ := f.envInfo(env)
	if e == nil || !f.canAdminister(env, user) {
		return fail(403, errForbidden)
	}
	if b.NewEpoch != e.epoch+1 {
		return fail(409, errConflict)
	}
	e.epoch, e.needsRotation = b.NewEpoch, false
	var keys fakeKeys
	_ = json.Unmarshal(fmt.Appendf(nil, `{"epoch":%d,"device":%q,"keys":%s}`, b.NewEpoch, b.Device, b.Keys), &keys)
	if status, err := f.storeKeys(user, env, keys); err != nil {
		return fail(status, err)
	}
	for _, v := range b.Versions {
		v.Epoch, v.Device = b.NewEpoch, b.Device
		if status, err := f.storeVersion(user, env, v, false); err != nil {
			return fail(status, err)
		}
	}
	return map[string]any{"epoch": b.NewEpoch}, 200, nil
}

// ---------------------------------------------------------------- machine tokens

func (f *fakeServer) postToken(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		AgeRecipient string   `json:"age_recipient"`
		Scope        []string `json:"scope"`
		CreatedAtUS  int64    `json:"created_at_us"`
		Signature    []byte   `json:"signature"`
		SecretHash   []byte   `json:"secret_hash"`
		ExpiresAt    string   `json:"expires_at"`
	}](r)
	if o == nil || !f.isAdmin(o.id, user) {
		return fail(403, errForbidden)
	}
	expiry, _ := time.Parse(time.RFC3339, b.ExpiresAt)
	f.tokens = append(f.tokens, &fakeToken{org: o.id, hash: b.SecretHash, expiry: expiry, json: tokenJSON{ID: b.ID, Name: b.Name, CreatedBy: user,
		AgeRecipient: b.AgeRecipient, Scope: b.Scope, CreatedAtUS: b.CreatedAtUS, Signature: b.Signature, ExpiresAt: b.ExpiresAt}})
	return map[string]string{"id": b.ID}, 201, nil
}

func (f *fakeServer) deleteToken(user string, r *http.Request) (any, int, error) {
	for _, t := range f.tokens {
		if t.json.ID == r.PathValue("id") && f.isAdmin(t.org, user) {
			now := time.Now().String()
			t.json.RevokedAt = &now
			f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
				return w.w.RecipientTokenID != nil && *w.w.RecipientTokenID == t.json.ID
			})
			f.startRotation(t.org, "machine token revoked", nil, &t.json.ID)
			return nil, 204, nil
		}
	}
	return fail(404, errNotFound)
}

func (f *fakeServer) machineEnvironment(_ string, r *http.Request) (any, int, error) {
	id, secret, ok := strings.Cut(strings.TrimPrefix(r.Header.Get("Authorization"), "EnvRune-Token "), ".")
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	var token *fakeToken
	for _, t := range f.tokens {
		if ok && err == nil && t.json.ID == id && t.json.RevokedAt == nil && time.Now().Before(t.expiry) && cloudcrypto.TokenSecretMatches(raw, t.hash) {
			token = t
		}
	}
	if token == nil {
		return fail(401, fmt.Errorf("the machine token is unknown, expired, or revoked"))
	}
	q := r.URL.Query()
	for _, e := range f.envs {
		_, p := f.envInfo(e.id)
		o := f.orgBySlug(q.Get("org"), token.json.CreatedBy)
		if o != nil && p.org == o.id && p.slug == q.Get("project") && e.slug == q.Get("env") {
			if o.id != token.org || !cloudcrypto.Allows(token.json.Scope, p.slug, e.slug) {
				return fail(403, errForbidden)
			}
			f.recordFetch(e.id, "token:"+id)
			f.read(e.id, fakeReader{token: id})
			return f.payload(e.id, func(w wrappedJSON) bool { return w.RecipientTokenID != nil && *w.RecipientTokenID == id }), 200, nil
		}
	}
	return fail(404, errNotFound)
}

// postEmergency takes a project's keys away from everyone but the owner's
// device and recovery recipient, revokes the tokens that reach it, and lists
// every secret of the project for rotation.
func (f *fakeServer) postEmergency(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	b := decode[struct{ Device string }](r)
	if o == nil || f.role(o.id, user).Role != "owner" {
		return fail(403, errForbidden)
	}
	var project *fakeProject
	for _, p := range f.projects {
		if p.org == o.id && p.slug == r.PathValue("project") {
			project = p
		}
	}
	if d := f.device(user, b.Device); project == nil || d == nil || d.Signature == nil || d.RevokedAt != nil {
		return fail(404, errNotFound)
	}
	tokens := []string{}
	now := time.Now().String()
	for _, t := range f.tokens {
		reaches := slices.ContainsFunc(t.json.Scope, func(s string) bool { return s == "*" || strings.HasPrefix(s, project.slug+"/") })
		if t.org == o.id && t.json.RevokedAt == nil && reaches {
			t.json.RevokedAt = &now
			tokens = append(tokens, t.json.ID)
		}
	}
	task := &fakeRotation{org: o.id, rotationJSON: rotationJSON{ID: fmt.Sprintf("rot-%d", len(f.rotations)+1), Reason: "emergency",
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	for _, e := range f.envs {
		if e.project != project.id {
			continue
		}
		e.needsRotation = true
		f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
			mine := w.w.RecipientUserID != nil && *w.w.RecipientUserID == user && (w.w.RecipientID == b.Device || w.w.RecipientID == "recovery")
			return w.env == e.id && !mine
		})
		for _, sec := range f.current(e.id) {
			task.Items = append(task.Items, struct {
				SecretID string `json:"secret_id"`
				Status   string `json:"status"`
			}{secretID(e.id, sec.Name), RotationPending})
		}
	}
	f.rotations = append(f.rotations, task)
	f.audit(o.id, user, "project.emergency", project.slug, `{}`)
	return map[string]any{"tokens": tokens, "secrets": len(task.Items)}, 200, nil
}

// ---------------------------------------------------------------- guided rotation

func (f *fakeServer) recordFetch(env, actor string) {
	if f.fetched[env] == nil {
		f.fetched[env] = map[string]bool{}
	}
	f.fetched[env][actor] = true
}

// startRotation lists every secret of the environments the subject fetched,
// and marks those environments for a new epoch.
func (f *fakeServer) startRotation(org, reason string, user, token *string, device ...*string) {
	actor := ""
	var subjectDevice *string
	switch {
	case len(device) == 1:
		actor, subjectDevice = "device:"+*user+":"+*device[0], device[0]
	case user != nil:
		actor = "user:" + *user
	default:
		actor = "token:" + *token
	}
	task := &fakeRotation{org: org, rotationJSON: rotationJSON{ID: fmt.Sprintf("rot-%d", len(f.rotations)+1), Reason: reason,
		SubjectUserID: user, SubjectToken: token, SubjectDevice: subjectDevice, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	for _, e := range f.envs {
		if _, p := f.envInfo(e.id); p.org != org || !f.fetched[e.id][actor] {
			continue
		}
		e.needsRotation = true
		for _, s := range f.current(e.id) {
			task.Items = append(task.Items, struct {
				SecretID string `json:"secret_id"`
				Status   string `json:"status"`
			}{secretID(e.id, s.Name), RotationPending})
		}
	}
	// A device that fetched nothing here leaves nothing to replace.
	if len(device) == 1 && len(task.Items) == 0 {
		return
	}
	f.rotations = append(f.rotations, task)
}

func (f *fakeServer) patchRotationItem(user string, r *http.Request) (any, int, error) {
	b := decode[struct{ Status string }](r)
	for _, task := range f.rotations {
		if task.ID != r.PathValue("task") {
			continue
		}
		if !f.isAdmin(task.org, user) {
			return fail(403, errForbidden)
		}
		if !slices.Contains([]string{RotationPending, RotationRotated, RotationAccepted}, b.Status) {
			return fail(400, fmt.Errorf("unknown status"))
		}
		for i := range task.Items {
			if task.Items[i].SecretID == r.PathValue("secret") {
				task.Items[i].Status = b.Status
			}
		}
		return nil, 204, nil
	}
	return fail(403, errForbidden)
}

// getVersions answers with version numbers only, to any member, and counts
// the questions so tests can tell a check from a fetch.
func (f *fakeServer) getVersions(user string, r *http.Request) (any, int, error) {
	f.checks++
	if f.unreachable {
		time.Sleep(200 * time.Millisecond)
	}
	out := map[string]envVersions{}
	for _, id := range r.URL.Query()["env"] {
		e, p := f.envInfo(id)
		if e == nil || f.role(p.org, user).Role == "" || f.role(p.org, user).Role == "removed" {
			continue
		}
		v := envVersions{Epoch: e.epoch, Secrets: map[string]uint64{}}
		for _, s := range f.current(id) {
			v.Secrets[s.Name] = s.Version
		}
		v.Sensitive = map[string]uint64{}
		for _, s := range f.sensitive {
			if s.json.EnvironmentID == id {
				v.Sensitive[s.json.Name] = s.json.Version
			}
		}
		out[id] = v
	}
	return out, 200, nil
}

// ---------------------------------------------------------------- sensitive secrets

func (f *fakeServer) getProxy(string, *http.Request) (any, int, error) {
	return map[string]string{"recipient": f.proxy.Recipient().String()}, 200, nil
}

func (f *fakeServer) postSensitive(user string, r *http.Request) (any, int, error) {
	env := r.PathValue("env")
	b := decode[struct {
		Name           string   `json:"name"`
		Version        uint64   `json:"version"`
		Hosts          []string `json:"hosts"`
		ProxyRecipient string   `json:"proxy_recipient"`
		Sealed         []byte   `json:"sealed"`
		Device         string   `json:"device"`
		Signature      []byte   `json:"signature"`
	}](r)
	e, p := f.envInfo(env)
	if e == nil || !f.isAdmin(p.org, user) || !f.canAdminister(env, user) {
		return fail(403, errForbidden)
	}
	if b.ProxyRecipient != f.proxy.Recipient().String() {
		return fail(409, fmt.Errorf("sealed for another proxy identity"))
	}
	for _, sec := range f.current(env) {
		if sec.Name == b.Name {
			return fail(409, fmt.Errorf("%s already exists as an ordinary secret", b.Name))
		}
	}
	id := secretID(env, b.Name)
	var current uint64
	if held := f.sensitive[id]; held != nil {
		current = held.json.Version
	}
	if b.Version != current+1 {
		return fail(409, errConflict)
	}
	hash := sha256.Sum256(b.Sealed)
	f.sensitive[id] = &fakeSensitive{sealed: b.Sealed, json: sensitiveJSON{EnvironmentID: env, Name: b.Name, Version: b.Version, Hosts: b.Hosts,
		ProxyRecipient: b.ProxyRecipient, SealedHash: hash[:], WriterUserID: user, WriterDeviceID: b.Device, Signature: b.Signature}}
	return map[string]any{"name": b.Name, "version": b.Version}, 201, nil
}

// forward plays POST /forward: it answers as the member may, opens each
// named secret with the proxy identity, refuses a host the sealed content
// does not allow, and puts the value in place of the placeholder in the
// address, the headers, and the body before calling the upstream.
func (f *fakeServer) forward(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	refuse := func(status int, message string) {
		w.Header().Set("X-EnvRune-Forward", "refused")
		writeJSON(w, status, map[string]string{"error": message})
	}
	claims, err := parseClaims(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || f.expired[r.Header.Get("Authorization")] {
		refuse(401, "sign in")
		return
	}
	user, device := claims.Subject, r.Header.Get("X-EnvRune-Device")
	var headers [][2]string
	var named []struct {
		EnvironmentID string `json:"environment_id"`
		Name          string `json:"name"`
		Placeholder   string `json:"placeholder"`
	}
	decode := func(header string, into any) bool {
		raw, err := base64.StdEncoding.DecodeString(r.Header.Get(header))
		return err == nil && json.Unmarshal(raw, into) == nil
	}
	if !decode("X-EnvRune-Headers", &headers) || !decode("X-EnvRune-Secrets", &named) || len(named) == 0 {
		refuse(400, "malformed")
		return
	}
	target, err := url.Parse(r.Header.Get("X-EnvRune-Target"))
	if err != nil || target.Scheme != "https" || target.Port() != "" {
		refuse(400, "sensitive secrets are sent only over https, on the standard port")
		return
	}
	body, _ := io.ReadAll(r.Body)
	swaps := [][2]string{} // placeholder, value
	for _, n := range named {
		e, _ := f.envInfo(n.EnvironmentID)
		d := f.device(user, device)
		if e == nil || !f.canUse(n.EnvironmentID, user) || d == nil || d.Signature == nil || d.RevokedAt != nil {
			refuse(403, "you cannot use this environment")
			return
		}
		stored := f.sensitive[secretID(n.EnvironmentID, n.Name)]
		if stored == nil {
			refuse(404, "no sensitive secret "+n.Name)
			return
		}
		_, p := f.envInfo(n.EnvironmentID)
		record := stored.json.record(p.org, p.id)
		record.Sealed = stored.sealed
		content, err := cloudcrypto.OpenSensitive(record, f.proxy)
		if err != nil || !slices.Contains(content.Hosts, strings.ToLower(target.Hostname())) {
			refuse(403, "a sensitive secret in this request may not be sent to "+target.Hostname())
			return
		}
		swaps = append(swaps, [2]string{n.Placeholder, string(content.Value)})
		f.forwarded[strings.Join([]string{user, device, n.Name, target.Hostname()}, " ")]++
	}
	put := func(text string) string {
		for _, sw := range swaps {
			text = strings.ReplaceAll(text, sw[0], sw[1])
		}
		return text
	}
	out := httptest.NewRequest(r.Method, put(target.String()), strings.NewReader(put(string(body))))
	for _, h := range headers {
		value := h[1]
		if basic, ok := strings.CutPrefix(value, "Basic "); ok && strings.EqualFold(h[0], "Authorization") {
			if raw, err := base64.StdEncoding.DecodeString(basic); err == nil {
				value = "Basic " + base64.StdEncoding.EncodeToString([]byte(put(string(raw))))
			}
		}
		out.Header.Add(h[0], put(value))
	}
	if f.upstream == nil {
		refuse(502, target.Hostname()+" could not be reached from the server")
		return
	}
	recorder := httptest.NewRecorder()
	f.upstream.ServeHTTP(recorder, out)
	answer := recorder.Body.String()
	for _, sw := range swaps {
		answer = strings.ReplaceAll(answer, sw[1], sw[0])
	}
	for name, values := range recorder.Header() {
		w.Header()[name] = values
	}
	w.Header().Set("X-EnvRune-Forward", "upstream")
	w.WriteHeader(recorder.Code)
	_, _ = io.WriteString(w, answer)
}

// ---------------------------------------------------------------- who has the current values

func (f *fakeServer) read(env string, reader fakeReader) {
	if f.lastFetch[env] == nil {
		f.lastFetch[env] = map[fakeReader]time.Time{}
	}
	f.lastFetch[env][reader] = time.Now()
}

func (f *fakeServer) getStatus(user string, r *http.Request) (any, int, error) {
	env := r.PathValue("env")
	e, p := f.envInfo(env)
	if e == nil || !(f.canAdminister(env, user) || slices.Contains([]string{"owner", "admin", "auditor"}, f.role(p.org, user).Role)) {
		return fail(403, errForbidden)
	}
	var out statusJSON
	for _, sec := range f.current(env) {
		row := struct {
			Name            string     `json:"name"`
			Version         uint64     `json:"version"`
			WrittenAt       time.Time  `json:"written_at"`
			TransitionUntil *time.Time `json:"transition_until"`
		}{Name: sec.Name, Version: sec.Version, WrittenAt: f.written[secretID(env, sec.Name)]}
		if until, ok := f.transition[secretID(env, sec.Name)]; ok {
			row.TransitionUntil = &until
		}
		out.Secrets = append(out.Secrets, row)
	}
	for reader, at := range f.lastFetch[env] {
		row := struct {
			UserID    *string   `json:"user_id"`
			DeviceID  *string   `json:"device_id"`
			TokenID   *string   `json:"token_id"`
			LastFetch time.Time `json:"last_fetch"`
		}{LastFetch: at}
		if reader.token != "" {
			row.TokenID = &reader.token
		} else {
			row.UserID, row.DeviceID = &reader.user, &reader.device
		}
		out.Fetches = append(out.Fetches, row)
	}
	return out, 200, nil
}

func (f *fakeServer) putTransition(user string, r *http.Request) (any, int, error) {
	env, name := r.PathValue("env"), r.PathValue("name")
	b := decode[struct {
		Until *time.Time `json:"until"`
	}](r)
	if e, _ := f.envInfo(env); e == nil || !f.canAdminister(env, user) {
		return fail(403, errForbidden)
	}
	if _, ok := f.written[secretID(env, name)]; !ok {
		return fail(404, errNotFound)
	}
	if b.Until == nil {
		delete(f.transition, secretID(env, name))
	} else {
		f.transition[secretID(env, name)] = *b.Until
	}
	return nil, 204, nil
}

func (f *fakeServer) postUse(user string, r *http.Request) (any, int, error) {
	env := r.PathValue("env")
	b := decode[struct {
		Device string `json:"device"`
		Uses   []struct {
			Names []string `json:"names"`
			At    string   `json:"at"`
		} `json:"uses"`
	}](r)
	e, p := f.envInfo(env)
	if e == nil || !f.canUse(env, user) {
		return fail(403, errForbidden)
	}
	if d := f.device(user, b.Device); d == nil || d.Signature == nil || d.RevokedAt != nil {
		return fail(403, errForbidden)
	}
	for _, u := range b.Uses {
		names, _ := json.Marshal(u.Names)
		f.audit(p.org, user, "secret.use", p.slug+"/"+e.slug, `{"at": "`+u.At+`", "names": `+string(names)+`, "reported_by_device": true}`)
	}
	return nil, 204, nil
}

// ---------------------------------------------------------------- audit

// audit appends to an organization's chain as the database trigger does.
func (f *fakeServer) audit(org, user, action, target, detail string) {
	f.auditID++
	e := AuditEntry{ID: f.auditID, OrgID: org, At: time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		ActorUserID: &user, Action: action, Target: target, Detail: json.RawMessage(detail), DetailText: detail}
	f.audits[org] = append(f.audits[org], e)
	f.rechain(org)
}

// rechain computes every hash of a chain again, as a server rewriting its
// log would.
func (f *fakeServer) rechain(org string) {
	var previous []byte
	for i := range f.audits[org] {
		e := &f.audits[org][i]
		at, _ := time.Parse(time.RFC3339Nano, e.At)
		text := fmt.Sprintf("%s\x1f%s.%06dZ\x1f%s\x1f%s\x1f%s\x1f%s", e.OrgID, at.Format("2006-01-02T15:04:05"), at.Nanosecond()/1000,
			*e.ActorUserID, e.Action, e.Target, e.DetailText)
		sum := sha256.Sum256(append(slices.Clone(previous), text...))
		e.PrevHash, e.Hash = previous, sum[:]
		previous = e.Hash
	}
}

// getAudit pages two entries at a time, so clients must follow pages.
func (f *fakeServer) getAudit(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	if o == nil {
		return fail(404, errNotFound)
	}
	out := []AuditEntry{}
	if !slices.Contains([]string{"owner", "admin", "auditor"}, f.role(o.id, user).Role) {
		return out, 200, nil
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	for _, e := range f.audits[o.id] {
		if e.ID > after && len(out) < 2 {
			out = append(out, e)
		}
	}
	return out, 200, nil
}

// ---------------------------------------------------------------- clients

// memStore is the vault's Store in memory.
type memStore struct {
	mu  sync.Mutex
	raw []byte
}

func (m *memStore) CloudState() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.raw...), nil
}

func (m *memStore) UpdateCloudState(change func([]byte) ([]byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := change(append([]byte(nil), m.raw...))
	if err != nil {
		return err
	}
	m.raw = next
	return nil
}

// accessToken is a JWT-shaped token the fake reads the user id from.
func accessToken(user, email string) string {
	claims, _ := json.Marshal(map[string]string{"sub": user, "email": email})
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
}

// signIn returns a device of user, signed in to the fake server, as a new
// vault would be after `envrune login`.
func (f *fakeServer) signIn(user string) *Service {
	f.mu.Lock()
	f.emails[user+"@example.com"] = user
	f.mu.Unlock()
	s := &Service{Store: &memStore{}, HTTP: f.srv.Client()}
	err := s.update(func(st *State) error {
		st.Server, st.UserID, st.Email = f.srv.URL, user, user+"@example.com"
		st.Tokens = Tokens{AccessToken: accessToken(user, user+"@example.com"), RefreshToken: "r"}
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fakeServer) accountKey(user string) ed25519.PublicKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.profiles[user].key
}
