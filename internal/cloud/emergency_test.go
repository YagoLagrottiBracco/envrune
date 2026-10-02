package cloud

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

func TestAnEmergencyTakesTheKeysFromEveryoneButTheOwner(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	must[uint64](t)(alice.Set(ctx, secret("db-url"), []byte("postgres://one")))
	ok(t, alice.CreateProject(ctx, "acme", "billing", "Billing"))
	ok(t, alice.CreateEnvironment(ctx, "acme", "billing", "production"))
	billing := Path{Org: "acme", Project: "billing", Env: "production", Name: "invoice-key"}
	must[uint64](t)(alice.Set(ctx, billing, []byte("inv_1")))
	bob := join(t, f, alice, "bob", cloudcrypto.RoleAdmin, "*")
	carol := join(t, f, alice, "carol", cloudcrypto.RoleConsumer, "shop/production")
	value(t, carol, production, "stripe-key")
	shopToken := must[string](t)(alice.CreateToken(ctx, "acme", "deploy", []string{"shop/production"}, time.Hour))
	billingToken := must[string](t)(alice.CreateToken(ctx, "acme", "billing", []string{"billing/production"}, time.Hour))

	if _, err := bob.Emergency(ctx, "acme", "shop"); err == nil {
		t.Fatal("an admin declared an emergency")
	}
	e := must[*Emergency](t)(alice.Emergency(ctx, "acme", "shop"))
	if !slices.Equal(e.Rotated, []string{"shop/production"}) || len(e.Tokens) != 1 || e.Secrets != 2 || len(e.Left) != 0 {
		t.Fatalf("the emergency did %+v", e)
	}

	// The owner still reads; nobody else has a key, though they are members.
	if got := value(t, alice, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("alice read %q", got)
	}
	for name, s := range map[string]*Service{"bob": bob, "carol": carol} {
		if _, err := s.Pull(ctx, production, false); !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s after the emergency: %v", name, err)
		}
	}
	if _, err := MachineValues(ctx, f.srv.Client(), f.srv.URL, shopToken, production); err == nil {
		t.Fatal("a token that reached the project still reads")
	}
	// Another project is untouched.
	if got := value(t, bob, billing, "invoice-key"); got != "inv_1" {
		t.Fatalf("bob read %q from another project", got)
	}
	must[map[string][]byte](t)(MachineValues(ctx, f.srv.Client(), f.srv.URL, billingToken, billing))

	// Every secret of the project is listed, whoever fetched it.
	tasks := must[[]RotationTask](t)(alice.Rotation(ctx, "acme"))
	if last := tasks[len(tasks)-1]; last.Reason != "emergency" || last.Pending() != 2 {
		t.Fatalf("the rotation is %+v", tasks)
	}
	// Access comes back when an administrator shares the new keys.
	must[int](t)(alice.Share(ctx, "acme"))
	if got := value(t, carol, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("after sharing, carol read %q", got)
	}
}
