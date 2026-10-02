//go:build e2e

package cloud

// End-to-end test against the real API (cloud/web) and database
// (cloud/supabase), which the in-memory fake only imitates. Run it with
// cloud/e2e.sh, which starts both locally.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

type e2e struct {
	t                                *testing.T
	server, supabase, secret, public string
	suffix                           string
}

func newE2E(t *testing.T) *e2e {
	e := &e2e{t: t, server: os.Getenv("ENVRUNE_E2E_SERVER"), supabase: os.Getenv("ENVRUNE_E2E_SUPABASE_URL"),
		secret: os.Getenv("ENVRUNE_E2E_SUPABASE_SECRET_KEY"), public: os.Getenv("ENVRUNE_E2E_SUPABASE_PUBLISHABLE_KEY")}
	if e.server == "" || e.supabase == "" || e.secret == "" || e.public == "" {
		t.Skip("set ENVRUNE_E2E_* or run cloud/e2e.sh")
	}
	raw := make([]byte, 4)
	_, _ = rand.Read(raw)
	e.suffix = hex.EncodeToString(raw)
	return e
}

func (e *e2e) post(url, key string, body any, out any) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("apikey", key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var failure map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&failure)
		e.t.Fatalf("%s: %s %v", url, resp.Status, failure)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			e.t.Fatal(err)
		}
	}
}

// user creates a confirmed account and returns a device signed in as it,
// as `envrune login` would leave a new vault.
func (e *e2e) user(name string) (*Service, string) {
	email := name + "-" + e.suffix + "@example.com"
	password := "e2e-" + e.suffix + "-" + name
	e.post(e.supabase+"/auth/v1/admin/users", e.secret, map[string]any{"email": email, "password": password, "email_confirm": true}, nil)
	return e.device(email, password), email
}

func (e *e2e) device(email, password string) *Service {
	var session struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    int64  `json:"expires_at"`
		User         struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	e.post(e.supabase+"/auth/v1/token?grant_type=password", e.public, map[string]string{"email": email, "password": password}, &session)
	s := &Service{Store: &memStore{}}
	err := s.update(func(st *State) error {
		st.Server, st.UserID, st.Email = e.server, session.User.ID, email
		st.Tokens = Tokens{AccessToken: session.AccessToken, RefreshToken: session.RefreshToken, ExpiresAt: session.ExpiresAt}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func read(t *testing.T, s *Service, path Path) (string, string) {
	t.Helper()
	must[[]SecretInfo](t)(s.Pull(ctx, path, false))
	values, role, err := s.Values(path)
	ok(t, err)
	return string(values[path.Name]), role
}

func TestEndToEnd(t *testing.T) {
	e := newE2E(t)
	org := "e2e-" + e.suffix
	prod := Path{Org: org, Project: "shop", Env: "production", Name: "stripe-key"}
	env := prod
	env.Name = ""

	// The founder creates the account, organization, and first secret.
	alice, aliceEmail := e.user("alice")
	setup := must[*SetupResult](t)(alice.Setup(ctx, "alice-laptop"))
	if !setup.Created {
		t.Fatalf("no account was created: %+v", setup)
	}
	must[*Org](t)(alice.CreateOrg(ctx, org, "E2E"))
	ok(t, alice.CreateProject(ctx, org, "shop", "Shop"))
	ok(t, alice.CreateEnvironment(ctx, org, "shop", "production"))
	must[uint64](t)(alice.Set(ctx, prod, []byte("sk_live_1")))
	if got, _ := read(t, alice, prod); got != "sk_live_1" {
		t.Fatalf("alice read %q", got)
	}

	// A consumer joins after the fingerprints are compared.
	bob, bobEmail := e.user("bob")
	must[*SetupResult](t)(bob.Setup(ctx, "bob-laptop"))
	found := must[*Account](t)(alice.LookupAccount(ctx, bobEmail))
	if found.Fingerprint != must[*Status](t)(bob.Status()).AccountFingerprint {
		t.Fatal("the fingerprints differ")
	}
	invited := must[*Handover](t)(alice.AddMember(ctx, org, found, cloudcrypto.RoleConsumer, []string{"shop/production"}))
	if _, err := bob.JoinOrg(ctx, org, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"); err == nil {
		t.Fatal("bob joined with a fingerprint that is not the organization's")
	}
	if joined := must[*Org](t)(bob.JoinOrg(ctx, org, invited.OrgFingerprint)); joined.Role != cloudcrypto.RoleConsumer {
		t.Fatalf("bob joined as %+v", joined)
	}
	// An organization with a second root holder, who signs members alone.
	trio := must[*Org](t)(alice.CreateOrg(ctx, org+"-b", "Two roots", found))
	if len(trio.Roots) != 2 {
		t.Fatalf("the second organization has %d roots", len(trio.Roots))
	}
	if joined := must[*Org](t)(bob.JoinOrg(ctx, org+"-b", trio.Fingerprint)); joined.Role != cloudcrypto.RoleOwner {
		t.Fatalf("the second root holder is %+v", joined)
	}
	if got, role := read(t, bob, prod); got != "sk_live_1" || role != cloudcrypto.RoleConsumer {
		t.Fatalf("bob read %q as %s", got, role)
	}
	if _, err := bob.Set(ctx, prod, []byte("x")); err == nil {
		t.Fatal("a consumer wrote a value")
	}

	// A second device of alice, approved by the first.
	laptop2 := e.device(aliceEmail, "e2e-"+e.suffix+"-alice")
	pending := must[*SetupResult](t)(laptop2.Setup(ctx, "alice-desktop"))
	id := must[*Status](t)(laptop2.Status()).DeviceID
	shown := must[*Device](t)(alice.PendingDevice(ctx, id))
	if !pending.Pending || shown.Fingerprint != pending.DeviceFingerprint {
		t.Fatalf("pending %+v, shown %s", pending, shown.Fingerprint)
	}
	must[int](t)(alice.ApproveDevice(ctx, id, shown.Fingerprint))
	if done := must[*SetupResult](t)(laptop2.Setup(ctx, "alice-desktop")); !done.Approved {
		t.Fatalf("not approved: %+v", done)
	}
	if got, _ := read(t, laptop2, prod); got != "sk_live_1" {
		t.Fatalf("the new device read %q", got)
	}

	// Recovery on a third device with the recovery key.
	recovered := e.device(aliceEmail, "e2e-"+e.suffix+"-alice")
	if n := must[int](t)(recovered.Recover(ctx, cloudcrypto.RecoveryKey(setup.RecoveryKey), "alice-new")); n < 1 {
		t.Fatalf("restored %d keys", n)
	}
	if got, _ := read(t, recovered, prod); got != "sk_live_1" {
		t.Fatalf("the recovered device read %q", got)
	}

	// A machine token reads its scope, and nothing after revocation.
	token := must[string](t)(alice.CreateToken(ctx, org, "ci", []string{"shop/production"}, time.Hour))
	values := must[map[string][]byte](t)(MachineValues(ctx, nil, e.server, token, env))
	if string(values["stripe-key"]) != "sk_live_1" {
		t.Fatalf("the token read %q", values["stripe-key"])
	}

	// A maintainer is removed: the environment rotates, and a value written
	// afterwards reaches everyone but them.
	carol, carolEmail := e.user("carol")
	must[*SetupResult](t)(carol.Setup(ctx, "carol-laptop"))
	must[*Handover](t)(alice.AddMember(ctx, org, must[*Account](t)(alice.LookupAccount(ctx, carolEmail)), cloudcrypto.RoleMaintainer, []string{"shop/*"}))
	if got, _ := read(t, carol, prod); got != "sk_live_1" {
		t.Fatalf("carol read %q", got)
	}
	// She writes the current value, so removing her must sign it again:
	// readers refuse what a former member signed.
	must[uint64](t)(carol.Set(ctx, prod, []byte("sk_live_1b")))
	carolID := must[*Status](t)(carol.Status()).UserID
	if h := must[*Handover](t)(alice.RemoveMember(ctx, org, carolID)); len(h.Rotated) != 1 || len(h.Left) != 0 {
		t.Fatalf("the removal handed over %+v", h)
	}
	if got, _ := read(t, bob, prod); got != "sk_live_1b" {
		t.Fatalf("after the removal bob read %q", got)
	}
	// Guided rotation: carol read the value, and the new epoch only encrypted
	// it again, so it waits until a new value is written.
	if tasks := must[[]RotationTask](t)(alice.Rotation(ctx, org)); len(tasks) != 1 || tasks[0].Subject != carolID || tasks[0].Pending() != 1 {
		t.Fatalf("after the removal, rotation is %+v", tasks)
	}
	must[uint64](t)(alice.Set(ctx, prod, []byte("sk_live_2")))
	if tasks := must[[]RotationTask](t)(alice.Rotation(ctx, org)); tasks[0].Pending() != 0 || tasks[0].Items[0].Status != RotationRotated {
		t.Fatalf("after the new value, rotation is %+v", tasks)
	}
	if _, err := carol.Pull(ctx, env, false); err == nil {
		t.Fatal("a removed member pulled")
	}
	if got, _ := read(t, bob, prod); got != "sk_live_2" {
		t.Fatalf("after the rotation bob read %q", got)
	}
	if values := must[map[string][]byte](t)(MachineValues(ctx, nil, e.server, token, env)); string(values["stripe-key"]) != "sk_live_2" {
		t.Fatalf("after the rotation the token read %q", values["stripe-key"])
	}

	tokenID := must[*cloudcrypto.MachineToken](t)(cloudcrypto.ParseMachineToken(token)).ID
	ok(t, alice.RevokeToken(ctx, tokenID))
	if _, err := MachineValues(ctx, nil, e.server, token, env); err == nil {
		t.Fatal("a revoked token read")
	}
	// The token read the value too; an admin may record that it stays.
	tasks := must[[]RotationTask](t)(alice.Rotation(ctx, org))
	if len(tasks) != 2 || tasks[1].Subject != "token "+tokenID || tasks[1].Pending() != 1 {
		t.Fatalf("after the revocation, rotation is %+v", tasks)
	}
	if _, err := bob.AcceptRotation(ctx, prod); err == nil {
		t.Fatal("a consumer accepted a rotation")
	}
	if n := must[int](t)(alice.AcceptRotation(ctx, prod)); n != 1 {
		t.Fatalf("accepted %d items", n)
	}
	if tasks := must[[]RotationTask](t)(alice.Rotation(ctx, org)); tasks[1].Pending() != 0 || tasks[1].Items[0].Status != RotationAccepted {
		t.Fatalf("after accepting, rotation is %+v", tasks)
	}

	// The organization as a member's CLI verifies it.
	shown2 := must[*Org](t)(bob.ShowOrg(ctx, org))
	for _, m := range shown2.Members {
		if !m.Verified {
			t.Fatalf("member %s did not verify", m.UserID)
		}
	}
	var apiErr *APIError
	if _, err := bob.Rotate(ctx, org, "shop", "production", false); err == nil || errors.As(err, &apiErr) {
		t.Fatalf("a consumer's rotation was not refused on the device: %v", err)
	}

	// A device learns of a new value by asking for version numbers, and
	// pulls only then.
	if pulled := must[[]Path](t)(bob.Freshen(ctx, []Path{env}, 5*time.Second)); len(pulled) != 0 {
		t.Fatalf("an up-to-date device pulled %v", pulled)
	}
	must[uint64](t)(alice.Set(ctx, prod, []byte("sk_live_3")))
	if pulled := must[[]Path](t)(bob.Freshen(ctx, []Path{env}, 5*time.Second)); len(pulled) != 1 {
		t.Fatalf("after a new value, freshen pulled %v", pulled)
	}
	if values, _, err := bob.Values(env); err != nil || string(values["stripe-key"]) != "sk_live_3" {
		t.Fatalf("bob has %q: %v", values["stripe-key"], err)
	}

	// The owner sees who has the new value: bob, who just pulled it, does.
	ok(t, alice.SetTransition(ctx, prod, time.Now().Add(time.Hour)))
	status := must[*EnvStatus](t)(alice.EnvironmentStatus(ctx, env))
	if len(status.Secrets) != 1 || status.Secrets[0].TransitionUntil.IsZero() {
		t.Fatalf("the status has %+v", status.Secrets)
	}
	bobID := must[*Status](t)(bob.Status()).UserID
	upToDate := false
	for _, r := range status.Readers {
		if r.UserID == bobID && len(r.Behind) == 0 {
			upToDate = true
		}
	}
	if !upToDate {
		t.Fatalf("bob does not show as up to date: %+v", status.Readers)
	}
	if _, err := bob.EnvironmentStatus(ctx, env); err == nil {
		t.Fatal("a consumer saw who synced")
	}
	// Bob's device notes a run and reports it the next time it is online.
	ok(t, bob.RecordUse(env, []string{"stripe-key"}))
	if n := must[int](t)(bob.ReportUse(ctx)); n != 1 {
		t.Fatalf("reported %d uses", n)
	}

	// A sensitive secret: sealed to the server's proxy identity after its
	// fingerprint is confirmed, listed for members with where it may go, and
	// in nobody's pull.
	proxy := must[*ProxyIdentity](t)(alice.Proxy(ctx))
	hidden := Path{Org: org, Project: "shop", Env: "production", Name: "payments-key"}
	if v := must[uint64](t)(alice.SetSensitive(ctx, hidden, []byte("the-real-value"), []string{"api.example.com"}, proxy.Fingerprint)); v != 1 {
		t.Fatalf("the sensitive secret is at version %d", v)
	}
	if _, err := alice.Set(ctx, hidden, []byte("x")); err == nil {
		t.Fatal("a sensitive secret was replaced by an ordinary one")
	}
	if _, err := alice.SetSensitive(ctx, prod, []byte("x"), []string{"api.example.com"}, proxy.Fingerprint); err == nil {
		t.Fatal("a secret members have read became sensitive")
	}
	listed := false
	for _, p := range must[*Org](t)(bob.ShowOrg(ctx, org)).Projects {
		for _, e := range p.Environments {
			for _, sec := range e.Sensitive {
				listed = listed || (sec.Name == "payments-key" && sec.Verified && len(sec.Hosts) == 1)
			}
		}
	}
	if !listed {
		t.Fatal("bob does not see the sensitive secret, verified")
	}
	must[[]SecretInfo](t)(bob.Pull(ctx, env, false))
	if values, _, err := bob.Values(env); err != nil || values["payments-key"] != nil {
		t.Fatalf("bob pulled the sensitive value: %v", err)
	}
	// Bob's requests go through the server, which opens the secret, checks
	// the host against what was sealed, and counts the use. The allowed host
	// does not exist, so the server reports that it could not reach it.
	fw := must[*Forwarder](t)(bob.Forwarder(ctx, []Path{hidden}))
	var refusal *ForwardError
	call := func(target string) *http.Request {
		req, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader([]byte(`{"k":"`+fw.Sealed()[0].Placeholder+`"}`)))
		req.Header.Set("Authorization", "Bearer "+fw.Sealed()[0].Placeholder)
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	if _, err := fw.Do(call("https://api.example.com/v1/charges")); !errors.As(err, &refusal) || refusal.Status != http.StatusBadGateway {
		t.Fatalf("forwarding to the allowed host: %v", err)
	}
	fw.sealed[0].Hosts = append(fw.sealed[0].Hosts, "example.org")
	if _, err := fw.Do(call("https://example.org/collect")); !errors.As(err, &refusal) || refusal.Status != http.StatusForbidden {
		t.Fatalf("the server forwarded to a host the secret does not allow: %v", err)
	}

	// A lost device: alice revokes her third one. It is cut off, the
	// environment it held a key for gets a new one, and what it fetched is
	// listed.
	lost := must[*Status](t)(recovered.Status()).DeviceID
	if h := must[*Handover](t)(alice.RevokeDevice(ctx, lost)); len(h.Rotated) == 0 {
		t.Fatalf("revoking a device rotated nothing: %+v", h)
	}
	if _, err := recovered.Pull(ctx, env, false); err == nil {
		t.Fatal("a revoked device pulled")
	}
	revoked := false
	for _, task := range must[[]RotationTask](t)(alice.Rotation(ctx, org)) {
		revoked = revoked || task.Reason == "device revoked"
	}
	if !revoked {
		t.Fatal("revoking a device opened no rotation")
	}

	// The offline limit is the admins' to set, and members' devices learn it.
	if err := bob.SetOfflineDays(ctx, org, 30); err == nil {
		t.Fatal("a consumer set the offline limit")
	}
	ok(t, alice.SetOfflineDays(ctx, org, 30))
	if shown := must[*Org](t)(bob.ShowOrg(ctx, org)); shown.OfflineDays != 30 {
		t.Fatalf("bob's device learned a limit of %d days", shown.OfflineDays)
	}
	ok(t, alice.SetOfflineDays(ctx, org, 0))

	// Rules: consumers are denied production, whatever their scope.
	ok(t, alice.SetPolicy(ctx, org, []PolicyRule{{Environments: "*/production", Deny: []string{cloudcrypto.RoleConsumer}}}))
	if err := bob.SetPolicy(ctx, org, nil); err == nil {
		t.Fatal("a consumer changed the rules")
	}
	if _, err := bob.Pull(ctx, env, false); err == nil {
		t.Fatal("a consumer fetched an environment the rules deny")
	}
	if rules := must[[]PolicyRule](t)(bob.Policy(ctx, org)); len(rules) != 1 {
		t.Fatalf("bob sees the rules %+v", rules)
	}
	ok(t, alice.SetPolicy(ctx, org, nil))
	must[[]SecretInfo](t)(bob.Pull(ctx, env, false))

	// An emergency: alice takes the project's keys from everyone, bob has
	// none until she shares the new ones.
	emergency := must[*Emergency](t)(alice.Emergency(ctx, org, "shop"))
	if len(emergency.Rotated) != 1 || emergency.Secrets == 0 {
		t.Fatalf("the emergency did %+v", emergency)
	}
	if _, err := bob.Pull(ctx, env, false); !errors.Is(err, ErrNoKey) {
		t.Fatalf("bob after the emergency: %v", err)
	}
	if _, err := bob.Emergency(ctx, org, "shop"); err == nil {
		t.Fatal("a consumer declared an emergency")
	}
	must[int](t)(alice.Share(ctx, org))
	if got, _ := read(t, bob, prod); got != "sk_live_3" {
		t.Fatalf("after sharing again bob read %q", got)
	}

	// The audit log's chain, as the database hashed it, verifies on the
	// device, and tells what happened above.
	audit := must[*AuditExport](t)(alice.Audit(ctx, org))
	seen := map[string]bool{}
	for _, entry := range audit.Entries {
		seen[entry.Action] = true
	}
	for _, action := range []string{"org.create", "member.consumer", "member.removed", "device.approve", "key.share", "secret.write",
		"secret.reencrypt", "environment.fetch", "environment.rotate", "token.create", "token.revoke", "rotation.accepted", "org.offline_days", "secret.transition", "secret.use", "secret.sensitive", "secret.forward", "device.revoke", "project.emergency", "policy.set"} {
		if !seen[action] {
			t.Errorf("the audit log has no %s", action)
		}
	}
	if again := must[*AuditExport](t)(alice.Audit(ctx, org)); again.Previous == nil || again.Previous.ID != audit.Head.ID {
		t.Fatalf("the second export did not continue the first: %+v", again.Previous)
	}
	if _, err := bob.Audit(ctx, org); err == nil {
		t.Fatal("a consumer read the audit log")
	}
}
