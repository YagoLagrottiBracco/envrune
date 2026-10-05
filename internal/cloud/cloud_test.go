package cloud

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

var ctx = context.Background()

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var production = Path{Org: "acme", Project: "shop", Env: "production"}

func secret(name string) Path { p := production; p.Name = name; return p }

// founder sets up alice with an organization, a project, a production
// environment, and one secret.
func founder(t *testing.T, f *fakeServer) (*Service, *SetupResult) {
	alice := f.signIn("alice")
	setup := must[*SetupResult](t)(alice.Setup(ctx, "alice-laptop"))
	if !setup.Created || len(setup.RecoveryKey) != 32 {
		t.Fatalf("the first device did not create the account: %+v", setup)
	}
	must[*Org](t)(alice.CreateOrg(ctx, "acme", "Acme"))
	ok(t, alice.CreateProject(ctx, "acme", "shop", "Shop"))
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "production"))
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_1")))
	return alice, setup
}

func value(t *testing.T, s *Service, path Path, name string) string {
	t.Helper()
	must[[]SecretInfo](t)(s.Pull(ctx, path, false))
	values, _, err := s.Values(path)
	ok(t, err)
	return string(values[name])
}

// join sets up user, and has alice add them after comparing fingerprints.
func join(t *testing.T, f *fakeServer, alice *Service, user, role string, scope ...string) *Service {
	t.Helper()
	s := f.signIn(user)
	must[*SetupResult](t)(s.Setup(ctx, user+"-laptop"))
	found := must[*Account](t)(alice.LookupAccount(ctx, user+"@example.com"))
	if status := must[*Status](t)(s.Status()); found.Fingerprint != status.AccountFingerprint {
		t.Fatalf("the admin saw %s, %s sees %s", found.Fingerprint, user, status.AccountFingerprint)
	}
	must[*Handover](t)(alice.AddMember(ctx, "acme", found, role, scope))
	return s
}

func TestMembersReadWhatTheirRoleAllows(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	if got := value(t, alice, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("alice read %q", got)
	}

	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	must[[]SecretInfo](t)(bob.Pull(ctx, production, false))
	values, role, err := bob.Values(production)
	ok(t, err)
	if string(values["stripe-key"]) != "sk_live_1" || role != cloudcrypto.RoleConsumer {
		t.Fatalf("bob read %q as %s", values["stripe-key"], role)
	}
	if _, err := bob.Set(ctx, secret("stripe-key"), []byte("x")); err == nil {
		t.Fatal("a consumer wrote a value")
	}

	// A new version reaches bob; the offline cache keeps the last pull.
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_2" {
		t.Fatalf("bob read %q after the update", got)
	}
	f.srv.Close()
	values, _, err = bob.Values(production)
	if err != nil || string(values["stripe-key"]) != "sk_live_2" {
		t.Fatalf("the cache did not work offline: %v", err)
	}
}

func TestNewDevicesAreApprovedByATrustedOne(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/*")

	for _, first := range []*Service{alice, bob} {
		user := must[*Status](t)(first.Status()).UserID
		second := f.signIn(user)
		pending := must[*SetupResult](t)(second.Setup(ctx, "desktop"))
		if !pending.Pending {
			t.Fatalf("%s's second device was not pending", user)
		}
		if _, err := second.Pull(ctx, production, false); !errors.Is(err, ErrNotApproved) {
			t.Fatalf("a pending device pulled: %v", err)
		}
		id := must[*Status](t)(second.Status()).DeviceID
		shown := must[*Device](t)(first.PendingDevice(ctx, id))
		if shown.Fingerprint != pending.DeviceFingerprint {
			t.Fatal("the two screens showed different fingerprints")
		}
		if _, err := first.ApproveDevice(ctx, id, "0000-0000"); err == nil {
			t.Fatal("a device was approved with the wrong fingerprint")
		}
		if shared := must[int](t)(first.ApproveDevice(ctx, id, shown.Fingerprint)); shared != 1 {
			t.Fatalf("%s shared %d keys", user, shared)
		}
		done := must[*SetupResult](t)(second.Setup(ctx, "desktop"))
		if !done.Approved || done.AccountFingerprint != must[*Status](t)(first.Status()).AccountFingerprint {
			t.Fatalf("the approval did not complete: %+v", done)
		}
		if got := value(t, second, production, "stripe-key"); got != "sk_live_1" {
			t.Fatalf("%s's new device read %q", user, got)
		}
	}
}

func TestRecoveryKeyRestoresAccess(t *testing.T) {
	f := newFakeServer(t)
	_, setup := founder(t, f)

	lost := f.signIn("alice")
	var wrong cloudcrypto.RecoveryKey
	_, _ = rand.Read(wrong[:])
	if _, err := lost.Recover(ctx, wrong, "new-laptop"); err == nil {
		t.Fatal("a wrong recovery key worked")
	}
	restored := must[int](t)(lost.Recover(ctx, cloudcrypto.RecoveryKey(setup.RecoveryKey), "new-laptop"))
	if restored != 1 {
		t.Fatalf("restored %d keys", restored)
	}
	if got := value(t, lost, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("read %q after recovery", got)
	}
	// The recovered device holds the account key: it can administer.
	must[uint64](t)(lost.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
}

func TestAResetRecoveryKeyReplacesTheOldOne(t *testing.T) {
	f := newFakeServer(t)
	alice, setup := founder(t, f)
	old := cloudcrypto.RecoveryKey(setup.RecoveryKey)

	// A device waiting for approval holds no account key, so it cannot.
	pending := f.signIn("alice")
	must[*SetupResult](t)(pending.Setup(ctx, "desktop"))
	if _, _, err := pending.ResetRecovery(ctx); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("a pending device replaced the recovery key: %v", err)
	}

	fresh, shared, err := alice.ResetRecovery(ctx)
	if err != nil || shared != 1 || fresh == old {
		t.Fatalf("reset shared %d keys, a new key %v: %v", shared, fresh != old, err)
	}

	lost := f.signIn("alice")
	if _, err := lost.Recover(ctx, old, "new-laptop"); err == nil {
		t.Fatal("the old recovery key still worked")
	}
	if restored := must[int](t)(lost.Recover(ctx, fresh, "new-laptop")); restored != 1 {
		t.Fatalf("the new key restored %d keys", restored)
	}
	if got := value(t, lost, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("read %q after recovery with the new key", got)
	}

	// Keys made later are wrapped for the new recipient too.
	must[uint64](t)(alice.Rotate(ctx, "acme", "shop", "production", false))
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	later := f.signIn("alice")
	if restored := must[int](t)(later.Recover(ctx, fresh, "another-laptop")); restored != 1 {
		t.Fatalf("after a rotation the new key restored %d keys", restored)
	}
	if got := value(t, later, production, "stripe-key"); got != "sk_live_2" {
		t.Fatalf("read %q after a rotation", got)
	}
}

func TestAnAccountKeyIsReplacedOutsideAnyOrganization(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleMaintainer, "shop/production")
	before := must[*Status](t)(bob.Status())
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("bob read %q", got)
	}

	// Not while an organization trusts the key, and never a root holder.
	if _, err := bob.ResetAccount(ctx, "bob-laptop"); err == nil || !strings.Contains(err.Error(), "in no organization") {
		t.Fatalf("a member reset the account: %v", err)
	}
	if _, err := alice.ResetAccount(ctx, "alice-laptop"); err == nil || !strings.Contains(err.Error(), "root holder") {
		t.Fatalf("a root holder reset the account: %v", err)
	}
	if after := must[*Status](t)(bob.Status()); after.AccountFingerprint != before.AccountFingerprint || after.DeviceID != before.DeviceID {
		t.Fatal("a refused reset changed this device's keys")
	}

	// Removed, bob resets: everything is new, and the old device is revoked.
	must[*Handover](t)(alice.RemoveMember(ctx, "acme", "bob"))
	reset, err := bob.ResetAccount(ctx, "bob-laptop")
	if err != nil {
		t.Fatal(err)
	}
	after := must[*Status](t)(bob.Status())
	if after.AccountFingerprint == before.AccountFingerprint || after.AccountFingerprint != reset.AccountFingerprint ||
		after.DeviceID == before.DeviceID || !after.DeviceApproved {
		t.Fatalf("after the reset: %+v", after)
	}
	devices := must[[]Device](t)(bob.Devices(ctx))
	for _, d := range devices {
		if d.Kind == cloudcrypto.KindDevice && d.ID != after.DeviceID && !d.Revoked {
			t.Fatalf("the old device %s is still trusted", d.ID)
		}
	}
	for _, check := range bob.Doctor(ctx) {
		if check.Level == CheckFail {
			t.Fatalf("the doctor on the reset account: %s", check.Message)
		}
	}

	// The administrator sees the new fingerprint and adds bob again; bob
	// reads what is there now, and the new recovery key restores it.
	found := must[*Account](t)(alice.LookupAccount(ctx, "bob@example.com"))
	if found.Fingerprint != reset.AccountFingerprint {
		t.Fatalf("the admin is shown %s, bob has %s", found.Fingerprint, reset.AccountFingerprint)
	}
	must[*Handover](t)(alice.AddMember(ctx, "acme", found, cloudcrypto.RoleMaintainer, []string{"shop/production"}))
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("bob read %q with the new account key", got)
	}
	lost := f.signIn("bob")
	if restored := must[int](t)(lost.Recover(ctx, reset.RecoveryKey, "bob-desktop")); restored != 1 {
		t.Fatalf("the new recovery key restored %d keys", restored)
	}
}

func TestRemovedMembersCannotReadWhatComesNext(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleMaintainer, "shop/production")
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("bob read %q", got)
	}

	rotated := must[*Handover](t)(alice.RemoveMember(ctx, "acme", "bob")).Rotated
	if len(rotated) != 1 || rotated[0] != "shop/production" {
		t.Fatalf("rotated %v", rotated)
	}
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	if got := value(t, alice, production, "stripe-key"); got != "sk_live_2" {
		t.Fatalf("alice read %q after the rotation", got)
	}

	// Even a server that lets bob back in has no key of the new epoch for him.
	f.mu.Lock()
	f.members["org-acme"]["bob"] = memberJSON{UserID: "bob", Role: "maintainer", Scope: []string{"shop/production"}}
	f.mu.Unlock()
	if _, err := bob.Pull(ctx, production, false); err == nil {
		t.Fatal("a removed member read the new epoch")
	}
}

func TestServerCannotAddARecipient(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	mallory := f.signIn("mallory")
	must[*SetupResult](t)(mallory.Setup(ctx, "mallory-laptop"))

	// The server lists mallory as a maintainer, with a certificate she
	// signed herself, and adds a device of its own to alice's account.
	rogue, _ := cloudcrypto.NewDevice("alice", "rogue")
	f.mu.Lock()
	f.members["org-acme"]["mallory"] = memberJSON{UserID: "mallory", Role: "maintainer", Scope: []string{"*"}}
	self, _ := cloudcrypto.NewAccount("mallory")
	cert, _ := self.Certify("org-acme", "mallory", f.profiles["mallory"].key, "maintainer", []string{"*"})
	f.certs = append(f.certs, certJSON{OrgID: cert.OrgID, UserID: cert.UserID, AccountKey: cert.AccountKey, Role: cert.Role, Scope: cert.Scope,
		IssuedAtUS: cert.IssuedAt.UnixMicro(), IssuerID: "mallory", Signature: cert.Signature})
	f.devices = append(f.devices, &deviceJSON{UserID: "alice", ID: "rogue", Kind: "device", AgeRecipient: rogue.Identity.Recipient().String(),
		SigningKey: rogue.SigningPublic(), CreatedAtUS: 1, Signature: make([]byte, 64)})
	f.mu.Unlock()

	must[int](t)(alice.Share(ctx, "acme"))
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.wrapped {
		if w.w.RecipientID == "rogue" || (w.w.RecipientUserID != nil && *w.w.RecipientUserID == "mallory") {
			t.Fatalf("alice wrapped a key for %s/%s", *w.w.RecipientUserID, w.w.RecipientID)
		}
	}
}

func TestServerCannotForgeOrRollBackValues(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	value(t, alice, production, "stripe-key")

	// Serving version 1 again after version 2 was seen.
	f.mu.Lock()
	env := "env-shop-production"
	saved := f.versions[env]
	f.versions[env] = saved[:1]
	f.mu.Unlock()
	if _, err := alice.Pull(ctx, production, false); !errors.Is(err, cloudcrypto.ErrRollback) {
		t.Fatalf("a rollback was not detected: %v", err)
	}
	must[[]SecretInfo](t)(alice.Pull(ctx, production, true))

	// A changed ciphertext, or one moved to another name.
	f.mu.Lock()
	tampered := append([]secretJSON(nil), saved...)
	tampered[1].Ciphertext = append([]byte(nil), tampered[1].Ciphertext...)
	tampered[1].Ciphertext[0] ^= 1
	f.versions[env] = tampered
	f.mu.Unlock()
	if _, err := alice.Pull(ctx, production, false); err == nil {
		t.Fatal("a tampered value was accepted")
	}
	f.mu.Lock()
	moved := append([]secretJSON(nil), saved...)
	moved[1].Name = "database-url"
	f.versions[env] = moved
	f.mu.Unlock()
	if _, err := alice.Pull(ctx, production, false); err == nil {
		t.Fatal("a value moved to another name was accepted")
	}
}

func TestMachineTokensReadTheirScopeWithoutTheServersWord(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "staging"))
	staging := Path{Org: "acme", Project: "shop", Env: "staging", Name: "stripe-key"}
	must[uint64](t)(alice.Set(ctx, staging, []byte("sk_test_1")))

	token := must[string](t)(alice.CreateToken(ctx, "acme", "ci", []string{"shop/production"}, 24*time.Hour))
	read := func(path Path) (map[string][]byte, error) {
		return MachineValues(ctx, f.srv.Client(), f.srv.URL, token, path)
	}
	values := must[map[string][]byte](t)(read(production))
	if string(values["stripe-key"]) != "sk_live_1" {
		t.Fatalf("the token read %q", values["stripe-key"])
	}
	if _, err := read(Path{Org: "acme", Project: "shop", Env: "staging"}); err == nil {
		t.Fatal("the token read outside its scope")
	}

	// It keeps working across a rotation, which wraps the new key for it.
	must[uint64](t)(alice.Rotate(ctx, "acme", "shop", "production", false))
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	if values := must[map[string][]byte](t)(read(production)); string(values["stripe-key"]) != "sk_live_2" {
		t.Fatalf("after rotation the token read %q", values["stripe-key"])
	}

	// A value written by a device the chain does not certify is refused.
	f.mu.Lock()
	versions := f.versions["env-shop-production"]
	versions[len(versions)-1].WriterDeviceID = "rogue"
	f.mu.Unlock()
	if _, err := read(production); !errors.Is(err, cloudcrypto.ErrUntrusted) {
		t.Fatalf("an uncertified writer was accepted: %v", err)
	}

	id := must[*cloudcrypto.MachineToken](t)(cloudcrypto.ParseMachineToken(token)).ID
	ok(t, alice.RevokeToken(ctx, id))
	if _, err := read(production); err == nil {
		t.Fatal("a revoked token still read")
	}
}

func TestLoginThroughTheLoopbackCallback(t *testing.T) {
	f := newFakeServer(t)
	s := &Service{Store: &memStore{}, HTTP: f.srv.Client()}
	post := func(address string, wrongState bool) {
		u, _ := url.Parse(address)
		state := u.Query().Get("state")
		if wrongState {
			state = "x" + state
		}
		form := url.Values{"state": {state}, "access_token": {accessToken("alice", "alice@example.com")}, "refresh_token": {"r"}, "expires_at": {"1"}}
		resp, err := http.PostForm("http://127.0.0.1:"+u.Query().Get("port")+"/callback", form)
		if err != nil {
			t.Error(err)
			return
		}
		resp.Body.Close()
		if wrongState != (resp.StatusCode == http.StatusBadRequest) {
			t.Errorf("the callback answered %d", resp.StatusCode)
		}
	}
	st := must[*State](t)(s.Login(ctx, f.srv.URL, func(address string) {
		if !strings.HasPrefix(address, f.srv.URL+"/cli/authorize?") {
			t.Errorf("opened %s", address)
		}
		go func() { post(address, true); post(address, false) }()
	}))
	if st.UserID != "alice" || st.Email != "alice@example.com" {
		t.Fatalf("signed in as %+v", st)
	}
	must[*SetupResult](t)(s.Setup(ctx, "laptop"))

	// The same vault cannot switch to another account.
	short, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := s.Login(short, f.srv.URL, func(address string) {
		go func() {
			u, _ := url.Parse(address)
			form := url.Values{"state": {u.Query().Get("state")}, "access_token": {accessToken("bob", "bob@example.com")}, "refresh_token": {"r"}}
			if resp, err := http.PostForm("http://127.0.0.1:"+u.Query().Get("port")+"/callback", form); err == nil {
				resp.Body.Close()
			}
		}()
	})
	if !errors.Is(err, ErrOtherAccount) {
		t.Fatalf("switched accounts: %v", err)
	}
	if _, err := s.Login(ctx, "http://example.com", func(string) {}); err == nil {
		t.Fatal("a plain http server was accepted")
	}
}

func TestUnwrapNeedsAnAdministratorOrTheRecipient(t *testing.T) {
	// A consumer may share with their own devices, never with anyone else.
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	carol := join(t, f, alice, "carol", cloudcrypto.RoleConsumer, "shop/production")
	value(t, carol, production, "stripe-key")

	// The server stores a key bob wrapped for carol as if it were hers.
	st := must[*State](t)(bob.state())
	device := must[*cloudcrypto.Device](t)(st.device())
	key := must[*cloudcrypto.EnvironmentKey](t)(cloudcrypto.NewEnvironmentKey("org-acme", "prj-shop", "env-shop-production", 1))
	carolState := must[*State](t)(carol.state())
	carolDevice := must[*cloudcrypto.Device](t)(carolState.device())
	carolAccount := must[*cloudcrypto.Account](t)(carolState.account())
	w := must[*cloudcrypto.WrappedKey](t)(device.Wrap(key, carolAccount.CertifyDevice(carolDevice.DeviceID, carolDevice.Identity.Recipient().String(), carolDevice.SigningPublic())))
	carolID := "carol"
	f.mu.Lock()
	for _, existing := range f.wrapped {
		if existing.w.RecipientUserID != nil && *existing.w.RecipientUserID == "carol" && existing.w.RecipientID == carolDevice.DeviceID {
			existing.w = wrappedJSON{Epoch: 1, RecipientUserID: &carolID, RecipientID: w.RecipientID, Wrapped: w.Wrapped,
				WrapperUserID: "bob", WrapperDeviceID: device.DeviceID, Signature: w.Signature}
		}
	}
	f.mu.Unlock()
	if _, err := carol.Pull(ctx, production, false); !errors.Is(err, cloudcrypto.ErrUntrusted) {
		t.Fatalf("carol accepted a key a consumer wrapped for her: %v", err)
	}
}

func TestReferencePaths(t *testing.T) {
	cases := []struct {
		ref, env, want string
		cloud, fails   bool
	}{
		{ref: "cloud.database-url", env: "production", want: "acme/shop/production/database-url", cloud: true},
		{ref: "cloud.acme.shared.staging.sentry-dsn", env: "production", want: "acme/shared/staging/sentry-dsn", cloud: true},
		{ref: "cloud.database-url", env: "", cloud: true, fails: true},
		{ref: "cloud.acme.shop.key", env: "dev", cloud: true, fails: true},
		{ref: "personal.cloud", env: "dev"},
		{ref: "team.stripe", env: "dev"},
	}
	for _, c := range cases {
		path, isCloud, err := ReferencePath(c.ref, "acme/shop", c.env)
		if isCloud != c.cloud || (err != nil) != c.fails || (err == nil && isCloud && path.String() != c.want) {
			t.Errorf("%s in %q: %v %v %v", c.ref, c.env, path, isCloud, err)
		}
	}
}

func TestSetAllWritesOnlyWhatChanged(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")

	written := must[map[string]uint64](t)(alice.SetAll(ctx, production, map[string][]byte{
		"stripe-key": []byte("sk_live_1"), "db-url": []byte("postgres://one"), "sentry-dsn": []byte("https://dsn")}))
	if len(written) != 2 || written["db-url"] != 1 || written["sentry-dsn"] != 1 {
		t.Fatalf("the first run wrote %v", written)
	}
	written = must[map[string]uint64](t)(alice.SetAll(ctx, production, map[string][]byte{
		"stripe-key": []byte("sk_live_1"), "db-url": []byte("postgres://two"), "sentry-dsn": []byte("https://dsn")}))
	if len(written) != 1 || written["db-url"] != 2 {
		t.Fatalf("the second run wrote %v", written)
	}
	if got := value(t, bob, production, "db-url"); got != "postgres://two" {
		t.Fatalf("bob read %q", got)
	}
	if _, err := alice.SetAll(ctx, production, map[string][]byte{"Not_A_Name": []byte("x")}); err == nil {
		t.Fatal("an invalid name was written")
	}
	if _, err := bob.SetAll(ctx, production, map[string][]byte{"db-url": []byte("x")}); err == nil {
		t.Fatal("a consumer wrote values")
	}
}
