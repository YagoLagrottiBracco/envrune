package cloud

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// A member who wrote values, shared keys, added members, and created tokens
// leaves signatures behind. Readers refuse a former member's signature, so
// the removal must sign all of it again.
func TestRemovingAnAdminHandsOverWhatTheySigned(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleAdmin, "shop/*")
	// Bob adds carol, which wraps the key again for everyone, writes a value,
	// and creates a token.
	carol := join(t, f, bob, "carol", cloudcrypto.RoleMaintainer, "shop/production")
	must[uint64](t)(bob.Set(ctx, secret("stripe-key"), []byte("sk_live_bob")))
	token := must[string](t)(bob.CreateToken(ctx, "acme", "ci", []string{"shop/production"}, time.Hour))
	tokenID := must[*cloudcrypto.MachineToken](t)(cloudcrypto.ParseMachineToken(token)).ID

	value(t, carol, production, "stripe-key")

	h := must[*Handover](t)(alice.RemoveMember(ctx, "acme", "bob"))
	if !slices.Equal(h.Rotated, []string{"shop/production"}) || !slices.Equal(h.Reissued, []string{"carol"}) ||
		!slices.Equal(h.Revoked, []string{tokenID}) || len(h.Left) != 0 || len(h.Orphaned) != 0 {
		t.Fatalf("the removal handed over %+v", h)
	}
	// Carol's copy is from before the removal. Once her device learns of it,
	// the copy no longer verifies, and says to pull the new epoch.
	must[*Org](t)(carol.ShowOrg(ctx, "acme"))
	if _, _, err := carol.Values(production); err == nil || !strings.Contains(err.Error(), "envrune cloud pull acme/shop/production") {
		t.Fatalf("a copy with a former member's signatures: %v", err)
	}
	for name, s := range map[string]*Service{"alice": alice, "carol": carol} {
		if got := value(t, s, production, "stripe-key"); got != "sk_live_bob" {
			t.Fatalf("%s read %q after the removal", name, got)
		}
	}
	if _, err := MachineValues(ctx, f.srv.Client(), f.srv.URL, token, production); err == nil {
		t.Fatal("a token the removed admin created still reads")
	}
	if _, err := bob.Pull(ctx, production, false); err == nil {
		t.Fatal("the removed admin pulled")
	}
	// Carol's membership now chains to alice, and she keeps working.
	must[uint64](t)(carol.Set(ctx, secret("stripe-key"), []byte("sk_live_carol")))
	if got := value(t, alice, production, "stripe-key"); got != "sk_live_carol" {
		t.Fatalf("alice read %q", got)
	}
}

func TestDemotingAWriterKeepsTheirValuesReadable(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleMaintainer, "shop/production")
	must[uint64](t)(bob.Set(ctx, secret("stripe-key"), []byte("sk_live_bob")))

	h := must[*Handover](t)(alice.ChangeMember(ctx, "acme", "bob", cloudcrypto.RoleConsumer, []string{"shop/production"}))
	if !slices.Equal(h.Rotated, []string{"shop/production"}) {
		t.Fatalf("the demotion handed over %+v", h)
	}
	must[[]SecretInfo](t)(bob.Pull(ctx, production, false))
	values, role, err := bob.Values(production)
	if err != nil || string(values["stripe-key"]) != "sk_live_bob" || role != cloudcrypto.RoleConsumer {
		t.Fatalf("bob read %q as %s: %v", values["stripe-key"], role, err)
	}
	if got := value(t, alice, production, "stripe-key"); got != "sk_live_bob" {
		t.Fatalf("alice read %q", got)
	}
	if _, err := bob.Set(ctx, secret("stripe-key"), []byte("x")); err == nil {
		t.Fatal("a consumer wrote a value")
	}
	// A change that takes nothing away rotates nothing.
	h = must[*Handover](t)(alice.ChangeMember(ctx, "acme", "bob", cloudcrypto.RoleMaintainer, []string{"shop/*"}))
	if len(h.Rotated) != 0 {
		t.Fatalf("a promotion rotated %v", h.Rotated)
	}
}

// An admin of one environment removes a member who also wrote to another.
// That one is left for someone who administers it, and until then readers
// refuse it rather than trust a former member's signature.
func TestEnvironmentsLeftBehindNeedAnExplicitRotation(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "staging"))
	staging := Path{Org: "acme", Project: "shop", Env: "staging"}
	dan := join(t, f, alice, "dan", cloudcrypto.RoleAdmin, "shop/production")
	erin := join(t, f, alice, "erin", cloudcrypto.RoleMaintainer, "shop/*")
	must[uint64](t)(erin.Set(ctx, Path{Org: "acme", Project: "shop", Env: "staging", Name: "db-url"}, []byte("postgres://staging")))

	h := must[*Handover](t)(dan.RemoveMember(ctx, "acme", "erin"))
	if !slices.Equal(h.Rotated, []string{"shop/production"}) || !slices.Equal(h.Left, []string{"shop/staging"}) {
		t.Fatalf("the removal handed over %+v", h)
	}
	if _, err := alice.Pull(ctx, staging, false); !errors.Is(err, ErrSignerLeft) {
		t.Fatalf("a former member's value was read, or refused without saying why: %v", err)
	}
	if _, err := alice.Rotate(ctx, "acme", "shop", "staging", false); !errors.Is(err, ErrSignerLeft) {
		t.Fatalf("a plain rotation accepted a former member's value: %v", err)
	}
	must[uint64](t)(alice.Rotate(ctx, "acme", "shop", "staging", true))
	if got := value(t, alice, staging, "db-url"); got != "postgres://staging" {
		t.Fatalf("alice read %q after the rotation", got)
	}

	// Accepting former members does not accept strangers: a writer the
	// chain never certified is refused either way.
	f.mu.Lock()
	versions := f.versions["env-shop-staging"]
	versions[len(versions)-1].WriterUserID = "mallory"
	f.mu.Unlock()
	if _, err := alice.Rotate(ctx, "acme", "shop", "staging", true); !errors.Is(err, cloudcrypto.ErrUntrusted) {
		t.Fatalf("an uncertified writer was accepted: %v", err)
	}
}

func TestAnAdminCannotSignAgainWhatTheyMayNotIssue(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateProject(ctx, "acme", "billing", "Billing"))
	ok(t, alice.CreateEnvironment(ctx, "acme", "billing", "production"))
	bob := join(t, f, alice, "bob", cloudcrypto.RoleAdmin, "*")
	dan := join(t, f, alice, "dan", cloudcrypto.RoleAdmin, "shop/*")
	join(t, f, bob, "erin", cloudcrypto.RoleMaintainer, "billing/*")
	join(t, f, bob, "frank", cloudcrypto.RoleConsumer, "shop/production")

	h := must[*Handover](t)(dan.RemoveMember(ctx, "acme", "bob"))
	if !slices.Equal(h.Reissued, []string{"frank"}) || !slices.Equal(h.Orphaned, []string{"erin"}) || !slices.Equal(h.Left, []string{"billing/production"}) {
		t.Fatalf("the removal handed over %+v", h)
	}
	org := must[*Org](t)(alice.ShowOrg(ctx, "acme"))
	verified := map[string]bool{}
	for _, m := range org.Members {
		verified[m.UserID] = m.Verified
	}
	if !verified["frank"] || verified["erin"] {
		t.Fatalf("after the removal, verified members are %v", verified)
	}
}
