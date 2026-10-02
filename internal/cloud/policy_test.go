package cloud

import (
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

func TestRulesDenyRolesAnEnvironmentWhateverTheirScope(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "staging"))
	staging := Path{Org: "acme", Project: "shop", Env: "staging"}
	must[uint64](t)(alice.Set(ctx, Path{Org: "acme", Project: "shop", Env: "staging", Name: "db-url"}, []byte("postgres://staging")))
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/*")
	carol := join(t, f, alice, "carol", cloudcrypto.RoleMaintainer, "shop/*")
	token := must[string](t)(alice.CreateToken(ctx, "acme", "deploy", []string{"shop/production"}, time.Hour))
	value(t, bob, production, "stripe-key")

	if err := carol.SetPolicy(ctx, "acme", []PolicyRule{{Environments: "*/production", Deny: []string{"consumer"}}}); err == nil {
		t.Fatal("a maintainer set the organization's rules")
	}
	for name, bad := range map[string][]PolicyRule{
		"denying owners":   {{Environments: "*/production", Deny: []string{"owner"}}},
		"denying nobody":   {{Environments: "*/production"}},
		"an unknown shape": {{Environments: "production", Deny: []string{"consumer"}}},
	} {
		if err := alice.SetPolicy(ctx, "acme", bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	ok(t, alice.SetPolicy(ctx, "acme", []PolicyRule{{Environments: "*/production", Deny: []string{"consumer"}}}))
	if rules := must[[]PolicyRule](t)(bob.Policy(ctx, "acme")); len(rules) != 1 || rules[0].Environments != "*/production" {
		t.Fatalf("bob sees the rules %+v", rules)
	}

	// The consumer is refused production, with the reason, and keeps staging.
	if _, err := bob.Pull(ctx, production, false); err == nil {
		t.Fatal("a consumer fetched an environment the rules deny")
	}
	if got := value(t, bob, staging, "db-url"); got != "postgres://staging" {
		t.Fatalf("bob read %q from staging", got)
	}
	// A new key for production is not wrapped for him, and the rotation
	// goes through although he is in scope.
	must[uint64](t)(alice.Rotate(ctx, "acme", "shop", "production", false))
	f.mu.Lock()
	for _, w := range f.wrapped {
		if w.env == "env-shop-production" && w.w.RecipientUserID != nil && *w.w.RecipientUserID == "bob" && w.w.Epoch == 2 {
			t.Error("the new key was wrapped for a member the rules deny")
		}
	}
	f.mu.Unlock()
	// Other roles and machine tokens are not touched.
	if got := value(t, carol, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("carol read %q", got)
	}
	must[map[string][]byte](t)(MachineValues(ctx, f.srv.Client(), f.srv.URL, token, production))
	// Sync skips what is denied instead of failing on it.
	synced := must[[]Path](t)(bob.Sync(ctx))
	if len(synced) != 1 || synced[0] != staging {
		t.Fatalf("bob synced %v", synced)
	}

	// "People never fetch it; machine tokens do": the owner still manages it.
	ok(t, alice.SetPolicy(ctx, "acme", []PolicyRule{{Environments: "shop/production", Deny: []string{"admin", "maintainer", "consumer"}}}))
	if _, err := carol.Pull(ctx, production, false); err == nil {
		t.Fatal("a maintainer fetched an environment the rules deny")
	}
	if _, err := carol.Set(ctx, secret("stripe-key"), []byte("x")); err == nil {
		t.Fatal("a maintainer wrote to an environment the rules deny")
	}
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	if values := must[map[string][]byte](t)(MachineValues(ctx, f.srv.Client(), f.srv.URL, token, production)); string(values["stripe-key"]) != "sk_live_2" {
		t.Fatalf("the token read %q", values["stripe-key"])
	}
	// Lifting the rules gives nothing back by itself: keys are shared again.
	ok(t, alice.SetPolicy(ctx, "acme", nil))
	must[int](t)(alice.Share(ctx, "acme"))
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_2" {
		t.Fatalf("after the rules were lifted bob read %q", got)
	}
}
