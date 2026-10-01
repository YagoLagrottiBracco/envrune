package cloud

import (
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// statuses maps each secret name of a task to its status.
func statuses(task RotationTask) map[string]string {
	out := map[string]string{}
	for _, i := range task.Items {
		out[i.Path.Name] = i.Status
	}
	return out
}

func TestGuidedRotationWaitsForNewValues(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	must[uint64](t)(alice.Set(ctx, secret("db-password"), []byte("hunter2")))
	bob := join(t, f, alice, "bob", cloudcrypto.RoleMaintainer, "shop/production")
	carol := join(t, f, alice, "carol", cloudcrypto.RoleConsumer, "shop/production")
	value(t, bob, production, "stripe-key")
	if tasks := must[[]RotationTask](t)(alice.Rotation(ctx, "acme")); len(tasks) != 0 {
		t.Fatalf("rotation before anyone left: %+v", tasks)
	}

	// Removing bob starts a new epoch, which encrypts both values again.
	// Bob still knows them, so both wait for a new value.
	must[[]string](t)(alice.RemoveMember(ctx, "acme", "bob"))
	tasks := must[[]RotationTask](t)(alice.Rotation(ctx, "acme"))
	if len(tasks) != 1 || tasks[0].Subject != "bob" || tasks[0].Reason != "member removed" || tasks[0].Pending() != 2 {
		t.Fatalf("after the removal: %+v", tasks)
	}
	if got := tasks[0].Items[0].Path; got != secret("db-password") {
		t.Fatalf("the first item is %s", got)
	}

	// A new value rotates its secret; a consumer cannot accept the other.
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	if _, err := carol.AcceptRotation(ctx, secret("db-password")); err == nil {
		t.Fatal("a consumer accepted a rotation")
	}
	got := statuses(must[[]RotationTask](t)(carol.Rotation(ctx, "acme"))[0])
	if got["stripe-key"] != RotationRotated || got["db-password"] != RotationPending {
		t.Fatalf("after one new value: %v", got)
	}

	if n := must[int](t)(alice.AcceptRotation(ctx, secret("db-password"))); n != 1 {
		t.Fatalf("accepted %d items", n)
	}
	task := must[[]RotationTask](t)(alice.Rotation(ctx, "acme"))[0]
	if task.Pending() != 0 || statuses(task)["db-password"] != RotationAccepted {
		t.Fatalf("after accepting: %+v", task)
	}
	if _, err := alice.AcceptRotation(ctx, secret("db-password")); err == nil {
		t.Fatal("accepted a secret that was not waiting")
	}
	if _, err := alice.AcceptRotation(ctx, secret("missing")); err == nil {
		t.Fatal("accepted a secret that does not exist")
	}
}

func TestRevokedTokensStartGuidedRotation(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	token := must[string](t)(alice.CreateToken(ctx, "acme", "ci", []string{"shop/production"}, time.Hour))
	must[map[string][]byte](t)(MachineValues(ctx, f.srv.Client(), f.srv.URL, token, production))
	id := must[*cloudcrypto.MachineToken](t)(cloudcrypto.ParseMachineToken(token)).ID
	ok(t, alice.RevokeToken(ctx, id))

	tasks := must[[]RotationTask](t)(alice.Rotation(ctx, "acme"))
	if len(tasks) != 1 || tasks[0].Subject != "token "+id || tasks[0].Pending() != 1 {
		t.Fatalf("after the revocation: %+v", tasks)
	}
	// The key the token held is replaced, and the value still waits.
	must[uint64](t)(alice.Rotate(ctx, "acme", "shop", "production"))
	if task := must[[]RotationTask](t)(alice.Rotation(ctx, "acme"))[0]; task.Pending() != 1 {
		t.Fatalf("a new epoch rotated the value: %+v", task)
	}
}
