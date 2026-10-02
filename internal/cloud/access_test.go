package cloud

import (
	"slices"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// expire makes a grant's time run out on the server, as the clock would.
func (f *fakeServer) expire(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, g := range f.grants {
		if g.ID == id {
			past := time.Now().Add(-time.Minute)
			g.ExpiresAt = &past
		}
	}
}

func TestAccessForALimitedTimeEndsOnTheServerByItself(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "staging"))
	staging := Path{Org: "acme", Project: "shop", Env: "staging"}
	must[uint64](t)(alice.Set(ctx, Path{Org: "acme", Project: "shop", Env: "staging", Name: "db-url"}, []byte("postgres://staging")))
	bob := join(t, f, alice, "bob", cloudcrypto.RoleMaintainer, "shop/staging")
	carol := join(t, f, alice, "carol", cloudcrypto.RoleMaintainer, "shop/*")

	if _, err := bob.Pull(ctx, production, false); err == nil {
		t.Fatal("bob read production before asking")
	}
	if _, err := bob.RequestAccess(ctx, "acme", []string{"shop/production"}, time.Minute, ""); err == nil {
		t.Fatal("a request for one minute was accepted")
	}
	id := must[string](t)(bob.RequestAccess(ctx, "acme", []string{"shop/production"}, 4*time.Hour, "incident 214"))
	if _, err := bob.RequestAccess(ctx, "acme", []string{"shop/production"}, time.Hour, ""); err == nil {
		t.Fatal("a second request was accepted while one waits")
	}
	// Bob sees his own request; an admin sees it; bob cannot approve it.
	if list := must[[]AccessGrant](t)(bob.AccessList(ctx, "acme")); len(list) != 1 || list[0].Status != "pending" || list[0].Reason != "incident 214" {
		t.Fatalf("bob's requests: %+v", list)
	}
	if _, err := bob.ApproveAccess(ctx, "acme", id); err == nil {
		t.Fatal("a maintainer approved his own request")
	}

	until := must[time.Time](t)(alice.ApproveAccess(ctx, "acme", id))
	if left := time.Until(until); left < 3*time.Hour || left > 5*time.Hour {
		t.Fatalf("the access holds for %s", left)
	}
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("with access, bob read %q", got)
	}

	// The time runs out: the server refuses him without anyone doing
	// anything, and he keeps what he had before.
	f.expire(id)
	if _, err := bob.Pull(ctx, production, false); err == nil {
		t.Fatal("bob read production after his access ran out")
	}
	if got := value(t, bob, staging, "db-url"); got != "postgres://staging" {
		t.Fatalf("bob read %q from staging", got)
	}
	if list := must[[]AccessGrant](t)(alice.AccessList(ctx, "acme")); !list[0].Expired() || !list[0].Open() {
		t.Fatalf("the grant is %+v", list[0])
	}
	// Someone else rotates production meanwhile: the new key is not wrapped
	// for him, and the rotation goes through.
	must[uint64](t)(carol.Rotate(ctx, "acme", "shop", "production", false))

	// An administrator's CLI finishes it: the scope is signed back, the
	// environment gets a new key, and what he fetched is listed.
	h := must[*Handover](t)(alice.EndAccess(ctx, "acme", id))
	if !slices.Equal(h.Rotated, []string{"shop/production"}) {
		t.Fatalf("ending the access handed over %+v", h)
	}
	org := must[*Org](t)(alice.ShowOrg(ctx, "acme"))
	for _, m := range org.Members {
		if m.UserID == "bob" && !slices.Equal(m.Scope, []string{"shop/staging"}) {
			t.Fatalf("bob's scope is %v", m.Scope)
		}
	}
	tasks := must[[]RotationTask](t)(alice.Rotation(ctx, "acme"))
	if len(tasks) != 1 || tasks[0].Reason != "access ended" || tasks[0].Subject != "bob" || tasks[0].Pending() != 1 {
		t.Fatalf("the rotation is %+v", tasks)
	}
	if list := must[[]AccessGrant](t)(alice.AccessList(ctx, "acme")); list[0].Status != "ended" || list[0].Open() {
		t.Fatalf("the grant is %+v", list[0])
	}
	if _, err := alice.EndAccess(ctx, "acme", id); err == nil {
		t.Fatal("an ended grant was ended again")
	}
}

func TestAccessCanBeDeniedEndedEarlyOrReplacedByADecision(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "staging"))
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/staging")

	denied := must[string](t)(bob.RequestAccess(ctx, "acme", []string{"shop/production"}, time.Hour, ""))
	ok(t, alice.DenyAccess(ctx, "acme", denied))
	if _, err := alice.ApproveAccess(ctx, "acme", denied); err == nil {
		t.Fatal("a denied request was approved")
	}
	if _, err := bob.Pull(ctx, production, false); err == nil {
		t.Fatal("bob read production after a denial")
	}

	// Ended early, before its time.
	early := must[string](t)(bob.RequestAccess(ctx, "acme", []string{"shop/production"}, time.Hour, ""))
	must[time.Time](t)(alice.ApproveAccess(ctx, "acme", early))
	value(t, bob, production, "stripe-key")
	must[*Handover](t)(alice.EndAccess(ctx, "acme", early))
	if _, err := bob.Pull(ctx, production, false); err == nil {
		t.Fatal("bob read production after his access was ended")
	}

	// An administrator who changes the member's scope has decided: the
	// grant ends, and its time running out later takes nothing away.
	kept := must[string](t)(bob.RequestAccess(ctx, "acme", []string{"shop/production"}, time.Hour, ""))
	must[time.Time](t)(alice.ApproveAccess(ctx, "acme", kept))
	must[*Handover](t)(alice.ChangeMember(ctx, "acme", "bob", cloudcrypto.RoleConsumer, []string{"shop/*"}))
	f.expire(kept)
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("after the scope was made his, bob read %q", got)
	}
}
