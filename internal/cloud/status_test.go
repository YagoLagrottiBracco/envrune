package cloud

import (
	"slices"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

func TestStatusTellsWhoHasTheNewValue(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	carol := join(t, f, alice, "carol", cloudcrypto.RoleMaintainer, "shop/production")
	value(t, bob, production, "stripe-key")
	value(t, carol, production, "stripe-key")
	token := must[string](t)(alice.CreateToken(ctx, "acme", "ci", []string{"shop/production"}, time.Hour))
	must[map[string][]byte](t)(MachineValues(ctx, f.srv.Client(), f.srv.URL, token, production))
	t.Cleanup(func() { now = time.Now })

	reader := func(status *EnvStatus, name string) ReaderStatus {
		t.Helper()
		for _, r := range status.Readers {
			if r.UserID == name || r.TokenID == name {
				return r
			}
		}
		t.Fatalf("no reader %s in %+v", name, status.Readers)
		return ReaderStatus{}
	}
	status := must[*EnvStatus](t)(alice.EnvironmentStatus(ctx, production))
	if len(status.Secrets) != 1 || len(reader(status, "bob").Behind) != 0 {
		t.Fatalf("before the rotation: %+v", status)
	}

	// Alice replaces the value and says the old one works for a day. Carol
	// syncs; bob and the token have not yet.
	time.Sleep(5 * time.Millisecond)
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	ok(t, alice.SetTransition(ctx, secret("stripe-key"), time.Now().Add(24*time.Hour)))
	time.Sleep(5 * time.Millisecond)
	must[[]Path](t)(carol.Freshen(ctx, []Path{production}, time.Second))

	status = must[*EnvStatus](t)(alice.EnvironmentStatus(ctx, production))
	if status.Secrets[0].Version != 2 || status.Secrets[0].TransitionUntil.IsZero() {
		t.Fatalf("the secret is %+v", status.Secrets[0])
	}
	tokenID := must[*cloudcrypto.MachineToken](t)(cloudcrypto.ParseMachineToken(token)).ID
	for name, behind := range map[string]bool{"alice": false, "carol": false, "bob": true, tokenID: true} {
		r := reader(status, name)
		if slices.Contains(r.Behind, "stripe-key") != behind || len(r.Stale) != 0 {
			t.Errorf("%s: behind %v, stale %v", name, r.Behind, r.Stale)
		}
	}
	// Once the transition has passed, what is still behind is stale.
	now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	status = must[*EnvStatus](t)(alice.EnvironmentStatus(ctx, production))
	if r := reader(status, "bob"); !slices.Contains(r.Stale, "stripe-key") {
		t.Fatalf("after the transition bob is %+v", r)
	}
	if r := reader(status, "carol"); len(r.Stale) != 0 {
		t.Fatalf("after the transition carol is %+v", r)
	}
	now = time.Now

	// Consumers do not see who synced or set transitions; maintainers do.
	if _, err := bob.EnvironmentStatus(ctx, production); err == nil {
		t.Fatal("a consumer saw who synced")
	}
	if err := bob.SetTransition(ctx, secret("stripe-key"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a consumer set a transition")
	}
	must[*EnvStatus](t)(carol.EnvironmentStatus(ctx, production))
	if err := alice.SetTransition(ctx, secret("stripe-key"), time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("a transition in the past was accepted")
	}
	if err := alice.SetTransition(ctx, secret("missing"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a transition for a secret that does not exist was accepted")
	}
}
