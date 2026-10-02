package cloud

import (
	"errors"
	"slices"
	"testing"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

var sensitivePath = Path{Org: "acme", Project: "shop", Env: "production", Name: "payments-key"}

// sensitiveList returns the production environment's sensitive secrets as s sees them.
func sensitiveList(t *testing.T, s *Service) []SensitiveInfo {
	t.Helper()
	for _, p := range must[*Org](t)(s.ShowOrg(ctx, "acme")).Projects {
		for _, e := range p.Environments {
			if p.Slug == "shop" && e.Slug == "production" {
				return e.Sensitive
			}
		}
	}
	t.Fatal("no shop/production")
	return nil
}

func TestSensitiveSecretsAreSealedToTheProxyAndWriteOnly(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	carol := join(t, f, alice, "carol", cloudcrypto.RoleMaintainer, "shop/production")

	proxy := must[*ProxyIdentity](t)(alice.Proxy(ctx))
	if proxy.Pinned || proxy.Fingerprint == "" {
		t.Fatalf("before the first use: %+v", proxy)
	}
	if _, err := alice.SetSensitive(ctx, sensitivePath, []byte("the-real-value"), []string{"api.example.com"}, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"); err == nil {
		t.Fatal("a fingerprint nobody confirmed was accepted")
	}
	if v := must[uint64](t)(alice.SetSensitive(ctx, sensitivePath, []byte("the-real-value"), []string{"api.example.com"}, proxy.Fingerprint)); v != 1 {
		t.Fatalf("version %d", v)
	}
	if again := must[*ProxyIdentity](t)(alice.Proxy(ctx)); !again.Pinned {
		t.Fatal("the proxy identity was not pinned")
	}

	// Only the proxy identity opens what the server stores.
	f.mu.Lock()
	stored := f.sensitive[secretID("env-shop-production", "payments-key")]
	record := stored.json.record("org-acme", "prj-shop")
	record.Sealed = stored.sealed
	identity := f.proxy
	f.mu.Unlock()
	content, err := cloudcrypto.OpenSensitive(record, identity)
	if err != nil || string(content.Value) != "the-real-value" || !slices.Equal(content.Hosts, []string{"api.example.com"}) {
		t.Fatalf("the proxy opened %+v: %v", content, err)
	}

	// Members see the name and the hosts, verified, and never a value: it is
	// not in what they pull, whatever their role.
	for name, s := range map[string]*Service{"alice": alice, "bob": bob, "carol": carol} {
		list := sensitiveList(t, s)
		if len(list) != 1 || list[0].Name != "payments-key" || !list[0].Verified || !slices.Equal(list[0].Hosts, []string{"api.example.com"}) {
			t.Fatalf("%s sees %+v", name, list)
		}
		must[[]SecretInfo](t)(s.Pull(ctx, production, false))
		values, _, err := s.Values(production)
		ok(t, err)
		if _, has := values["payments-key"]; has {
			t.Fatalf("%s pulled the sensitive value", name)
		}
	}

	// Marking is for owners and admins; a name is one kind of secret.
	fingerprint := proxy.Fingerprint
	if _, err := carol.SetSensitive(ctx, Path{Org: "acme", Project: "shop", Env: "production", Name: "other"}, []byte("x"), []string{"api.example.com"}, fingerprint); err == nil {
		t.Fatal("a maintainer marked a secret sensitive")
	}
	if _, err := alice.SetSensitive(ctx, secret("stripe-key"), []byte("x"), []string{"api.example.com"}, fingerprint); err == nil {
		t.Fatal("an ordinary secret, which members have read, became sensitive")
	}
	if _, err := alice.Set(ctx, sensitivePath, []byte("x")); err == nil {
		t.Fatal("a sensitive secret was overwritten by an ordinary one")
	}
	if _, err := alice.SetSensitive(ctx, sensitivePath, []byte("x"), []string{"*.example.com"}, fingerprint); err == nil {
		t.Fatal("a wildcard host was accepted")
	}
	// Rotating it is setting a new value.
	if v := must[uint64](t)(alice.SetSensitive(ctx, sensitivePath, []byte("the-next-value"), []string{"api.example.com", "b.example.org"}, fingerprint)); v != 2 {
		t.Fatalf("version %d", v)
	}
}

func TestAServerCannotSwapItsProxyIdentityOrTheHosts(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	proxy := must[*ProxyIdentity](t)(alice.Proxy(ctx))
	must[uint64](t)(alice.SetSensitive(ctx, sensitivePath, []byte("the-real-value"), []string{"api.example.com"}, proxy.Fingerprint))

	// The server changes the hosts it shows: the signature no longer holds.
	f.mu.Lock()
	stored := f.sensitive[secretID("env-shop-production", "payments-key")]
	stored.json.Hosts = []string{"evil.example.net"}
	f.mu.Unlock()
	if list := sensitiveList(t, bob); len(list) != 1 || list[0].Verified {
		t.Fatalf("changed hosts verified: %+v", list)
	}

	// The server presents another proxy identity: a device that pinned the
	// first one refuses to seal to it.
	f.mu.Lock()
	f.proxy, _ = age.GenerateX25519Identity()
	f.mu.Unlock()
	if _, err := alice.Proxy(ctx); !errors.Is(err, ErrProxyChanged) {
		t.Fatalf("another proxy identity was accepted: %v", err)
	}
	if _, err := alice.SetSensitive(ctx, sensitivePath, []byte("x"), []string{"api.example.com"}, proxy.Fingerprint); !errors.Is(err, ErrProxyChanged) {
		t.Fatalf("a value was sealed to another proxy identity: %v", err)
	}
}
