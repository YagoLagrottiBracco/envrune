package cloud

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// account sets up user's keys and returns them as the founder looks them up.
func account(t *testing.T, f *fakeServer, founder *Service, user string) (*Service, *Account) {
	t.Helper()
	s := f.signIn(user)
	must[*SetupResult](t)(s.Setup(ctx, user+"-laptop"))
	return s, must[*Account](t)(founder.LookupAccount(ctx, user+"@example.com"))
}

func TestExtraRootHoldersKeepTheOrganizationAlive(t *testing.T) {
	f := newFakeServer(t)
	alice := f.signIn("alice")
	must[*SetupResult](t)(alice.Setup(ctx, "alice-laptop"))
	bob, bobAccount := account(t, f, alice, "bob")
	_, carolAccount := account(t, f, alice, "carol")
	_, danAccount := account(t, f, alice, "dan")

	if _, err := alice.CreateOrg(ctx, "acme", "Acme", bobAccount, carolAccount, danAccount); err == nil {
		t.Fatal("three more root holders were accepted")
	}
	if _, err := alice.CreateOrg(ctx, "acme", "Acme", bobAccount, bobAccount); err == nil {
		t.Fatal("one account was accepted twice")
	}
	org := must[*Org](t)(alice.CreateOrg(ctx, "acme", "Acme", bobAccount, carolAccount))
	if len(org.Roots) != 3 || org.FirstSeen || org.Fingerprint == "" {
		t.Fatalf("the organization: %+v", org)
	}
	ok(t, alice.CreateProject(ctx, "acme", "shop", "Shop"))
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "production"))
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_1")))

	// Another root holder reads, and signs members the founder's devices
	// accept, with no certificate of their own: the pinned root is enough.
	joined := must[*Org](t)(bob.JoinOrg(ctx, "acme", org.Fingerprint))
	if joined.Role != cloudcrypto.RoleOwner || joined.FirstSeen {
		t.Fatalf("bob joined as %+v", joined)
	}
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("bob read %q", got)
	}
	erin := join(t, f, bob, "erin", cloudcrypto.RoleAdmin, "shop/*")
	if got := value(t, erin, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("erin read %q", got)
	}
	for _, m := range must[*Org](t)(alice.ShowOrg(ctx, "acme")).Members {
		if !m.Verified {
			t.Fatalf("alice does not verify %s", m.UserID)
		}
	}
	// A root holder cannot be removed, by the founder either.
	if _, err := alice.RemoveMember(ctx, "acme", "bob"); err == nil {
		t.Fatal("a root holder was removed")
	}
	// CI pins the whole set.
	token := must[string](t)(alice.CreateToken(ctx, "acme", "ci", []string{"shop/production"}, time.Hour))
	if roots := must[*cloudcrypto.MachineToken](t)(cloudcrypto.ParseMachineToken(token)).Roots; len(roots) != 3 {
		t.Fatalf("the token pins %d roots", len(roots))
	}
}

func TestServerCannotAddARootOfItsOwn(t *testing.T) {
	f := newFakeServer(t)
	alice := f.signIn("alice")
	must[*SetupResult](t)(alice.Setup(ctx, "alice-laptop"))
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	f.mu.Lock()
	f.profiles["mallory"] = &fakeProfile{key: public}
	f.injectRoot = &accountKeyJSON{UserID: "mallory", AccountKey: public}
	f.mu.Unlock()

	if _, err := alice.CreateOrg(ctx, "acme", "Acme"); !errors.Is(err, cloudcrypto.ErrUntrusted) {
		t.Fatalf("an organization with a root nobody chose: %v", err)
	}
	if st := must[*State](t)(alice.state()); st.Orgs["acme"] != nil {
		t.Fatal("the device kept a pin on roots nobody chose")
	}
}

func TestJoiningChecksTheFingerprintBeforeTrustingTheRoots(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob, bobAccount := account(t, f, alice, "bob")
	h := must[*Handover](t)(alice.AddMember(ctx, "acme", bobAccount, cloudcrypto.RoleConsumer, []string{"shop/production"}))
	if h.OrgFingerprint == "" || h.OrgFingerprint != must[*Org](t)(alice.ShowOrg(ctx, "acme")).Fingerprint {
		t.Fatalf("the invitation carries %q", h.OrgFingerprint)
	}

	// A server showing bob other roots is caught, and nothing is pinned.
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	f.mu.Lock()
	real := f.orgs[0].roots
	f.orgs[0].roots = []accountKeyJSON{{UserID: "alice", AccountKey: public}}
	f.mu.Unlock()
	if _, err := bob.JoinOrg(ctx, "acme", h.OrgFingerprint); !errors.Is(err, cloudcrypto.ErrUntrusted) {
		t.Fatalf("bob joined an organization with other roots: %v", err)
	}
	if st := must[*State](t)(bob.state()); st.Orgs["acme"] != nil && st.Orgs["acme"].ID != "" {
		t.Fatal("bob's device pinned roots that did not match")
	}

	// The real ones match, however the fingerprint is typed.
	f.mu.Lock()
	f.orgs[0].roots = real
	f.mu.Unlock()
	typed := " " + strings.ToLower(h.OrgFingerprint) + "\n"
	if org := must[*Org](t)(bob.JoinOrg(ctx, "acme", typed)); org.FirstSeen || org.Role != cloudcrypto.RoleConsumer {
		t.Fatalf("bob joined as %+v", org)
	}
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("bob read %q", got)
	}
	// Once pinned, it is the pin that a fingerprint is checked against.
	f.mu.Lock()
	f.orgs[0].roots = []accountKeyJSON{{UserID: "alice", AccountKey: public}}
	f.mu.Unlock()
	if _, err := bob.JoinOrg(ctx, "acme", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"); !errors.Is(err, cloudcrypto.ErrUntrusted) {
		t.Fatalf("a wrong fingerprint was accepted: %v", err)
	}
}
