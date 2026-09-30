package cloud

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	tokens   []*fakeToken
	fetches  int
}

type fakeProfile struct{ key, backup []byte }

type fakeOrg struct {
	id, slug, name string
	roots          []accountKeyJSON
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

type fakeToken struct {
	json   tokenJSON
	org    string
	hash   []byte
	expiry time.Time
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, emails: map[string]string{}, profiles: map[string]*fakeProfile{}, members: map[string]map[string]memberJSON{},
		versions: map[string][]secretJSON{}}
	mux := http.NewServeMux()
	route := func(pattern string, h func(user string, r *http.Request) (any, int, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			user := ""
			if !strings.Contains(pattern, "/health") && !strings.Contains(pattern, "/machine/") {
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
		return map[string]any{"service": "envrune-cloud", "api": 1}, 200, nil
	})
	route("GET /api/v1/account", f.getAccount)
	route("POST /api/v1/account", f.postAccount)
	route("GET /api/v1/accounts", f.getAccounts)
	route("POST /api/v1/devices", f.postDevice)
	route("POST /api/v1/devices/{id}/approve", f.approveDevice)
	route("DELETE /api/v1/devices/{id}", f.revokeDevice)
	route("GET /api/v1/orgs", f.getOrgs)
	route("POST /api/v1/orgs", f.postOrg)
	route("GET /api/v1/orgs/{org}", f.getOrg)
	route("POST /api/v1/orgs/{org}/members", f.postMember)
	route("POST /api/v1/orgs/{org}/projects", f.postProject)
	route("POST /api/v1/orgs/{org}/projects/{project}/environments", f.postEnvironment)
	route("POST /api/v1/orgs/{org}/tokens", f.postToken)
	route("DELETE /api/v1/tokens/{id}", f.deleteToken)
	route("GET /api/v1/environments/{env}", f.getEnvironment)
	route("PUT /api/v1/environments/{env}/keys", f.putKeys)
	route("POST /api/v1/environments/{env}/secrets", f.postSecret)
	route("POST /api/v1/environments/{env}/rotate", f.postRotate)
	route("GET /api/v1/machine/environment", f.machineEnvironment)
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
	return e != nil && slices.Contains([]string{"owner", "admin", "maintainer", "consumer"}, m.Role) && cloudcrypto.Allows(m.Scope, p.slug, e.slug)
}

func (f *fakeServer) canAdminister(env, user string) bool {
	e, p := f.envInfo(env)
	m := f.role(p.org, user)
	return e != nil && slices.Contains([]string{"owner", "admin", "maintainer"}, m.Role) && cloudcrypto.Allows(m.Scope, p.slug, e.slug)
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
	f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
		return w.w.RecipientUserID != nil && *w.w.RecipientUserID == user && w.w.RecipientID == d.ID
	})
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
	b := decode[struct{ Slug, Name string }](r)
	if f.profiles[user] == nil {
		return fail(404, errNotFound)
	}
	o := &fakeOrg{id: "org-" + b.Slug, slug: b.Slug, name: b.Name, roots: []accountKeyJSON{{UserID: user, AccountKey: f.profiles[user].key}}}
	f.orgs = append(f.orgs, o)
	f.members[o.id] = map[string]memberJSON{user: {UserID: user, Role: "owner", Scope: []string{"*"}}}
	return map[string]string{"id": o.id}, 201, nil
}

func (f *fakeServer) getOrg(user string, r *http.Request) (any, int, error) {
	o := f.orgBySlug(r.PathValue("org"), user)
	if o == nil {
		return fail(404, errNotFound)
	}
	snap := Snapshot{ID: o.id, Slug: o.slug, Name: o.name, Roots: o.roots}
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
	return snap, 200, nil
}

func (f *fakeServer) secretMeta(env string) []secretMeta {
	var out []secretMeta
	for _, s := range f.current(env) {
		out = append(out, secretMeta{Name: s.Name, CurrentVersion: s.Version})
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
	f.certs = append(f.certs, certJSON{OrgID: o.id, UserID: b.UserID, AccountKey: f.profiles[b.UserID].key, Role: b.Role, Scope: b.Scope,
		IssuedAtUS: b.IssuedAtUS, IssuerID: user, Signature: b.Signature})
	f.members[o.id][b.UserID] = memberJSON{UserID: b.UserID, Role: b.Role, Scope: b.Scope}
	if b.Role == "removed" {
		f.wrapped = slices.DeleteFunc(f.wrapped, func(w *fakeWrapped) bool {
			_, p := f.envInfo(w.env)
			return p.org == o.id && w.w.RecipientUserID != nil && *w.w.RecipientUserID == b.UserID
		})
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

func (f *fakeServer) storeVersion(user, env string, b fakeVersion) (int, error) {
	e, _ := f.envInfo(env)
	if e == nil || !f.canAdminister(env, user) {
		return 403, errForbidden
	}
	if b.Epoch != e.epoch {
		return 409, errConflict
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
	return 201, nil
}

func (f *fakeServer) postSecret(user string, r *http.Request) (any, int, error) {
	status, err := f.storeVersion(user, r.PathValue("env"), decode[fakeVersion](r))
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
		if status, err := f.storeVersion(user, env, v); err != nil {
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
			return f.payload(e.id, func(w wrappedJSON) bool { return w.RecipientTokenID != nil && *w.RecipientTokenID == id }), 200, nil
		}
	}
	return fail(404, errNotFound)
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
