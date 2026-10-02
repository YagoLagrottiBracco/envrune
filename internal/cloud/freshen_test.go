package cloud

import (
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

func TestFreshenPullsOnlyWhatMoved(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "staging"))
	staging := Path{Org: "acme", Project: "shop", Env: "staging"}
	must[uint64](t)(alice.Set(ctx, Path{Org: "acme", Project: "shop", Env: "staging", Name: "db-url"}, []byte("postgres://one")))
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/*")
	both := []Path{production, staging}
	fetches := func() int { f.mu.Lock(); defer f.mu.Unlock(); return f.fetches }

	// With no copy yet, freshening is the first pull.
	if pulled := must[[]Path](t)(bob.Freshen(ctx, both, time.Second)); len(pulled) != 2 {
		t.Fatalf("the first freshen pulled %v", pulled)
	}
	// Nothing moved: one question, no fetch.
	before := fetches()
	if pulled := must[[]Path](t)(bob.Freshen(ctx, both, time.Second)); len(pulled) != 0 || fetches() != before {
		t.Fatalf("an up-to-date device pulled %v (%d fetches)", pulled, fetches()-before)
	}

	// A new value, a new secret, and a new epoch each bring one environment.
	must[uint64](t)(alice.Set(ctx, secret("stripe-key"), []byte("sk_live_2")))
	if pulled := must[[]Path](t)(bob.Freshen(ctx, both, time.Second)); len(pulled) != 1 || pulled[0] != production {
		t.Fatalf("after a new value, freshen pulled %v", pulled)
	}
	if values, _, err := bob.Values(production); err != nil || string(values["stripe-key"]) != "sk_live_2" {
		t.Fatalf("bob has %q: %v", values["stripe-key"], err)
	}
	must[uint64](t)(alice.Set(ctx, Path{Org: "acme", Project: "shop", Env: "staging", Name: "extra"}, []byte("x")))
	if pulled := must[[]Path](t)(bob.Freshen(ctx, both, time.Second)); len(pulled) != 1 || pulled[0] != staging {
		t.Fatalf("after a new secret, freshen pulled %v", pulled)
	}
	must[uint64](t)(alice.Rotate(ctx, "acme", "shop", "production", false))
	if pulled := must[[]Path](t)(bob.Freshen(ctx, both, time.Second)); len(pulled) != 1 || pulled[0] != production {
		t.Fatalf("after a new epoch, freshen pulled %v", pulled)
	}
}

func TestFreshenKeepsTheCopyWhenTheServerIsOutOfReach(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	value(t, alice, production, "stripe-key")
	f.mu.Lock()
	f.unreachable = true
	f.mu.Unlock()

	started := time.Now()
	if _, err := alice.Freshen(ctx, []Path{production}, 50*time.Millisecond); err == nil {
		t.Fatal("a server that did not answer in time was waited for")
	}
	if waited := time.Since(started); waited > 150*time.Millisecond {
		t.Fatalf("freshen waited %s", waited)
	}
	if values, _, err := alice.Values(production); err != nil || string(values["stripe-key"]) != "sk_live_1" {
		t.Fatalf("the copy was lost: %v", err)
	}
	// Signed out, it asks nothing.
	ok(t, alice.Logout())
	if pulled, err := alice.Freshen(ctx, []Path{production}, time.Second); err != nil || len(pulled) != 0 {
		t.Fatalf("signed out, freshen = %v, %v", pulled, err)
	}
}

func TestFreshenRenewsACopyBeforeItExpires(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.SetOfflineDays(ctx, "acme", 30))
	value(t, alice, production, "stripe-key")
	t.Cleanup(func() { now = time.Now })

	now = func() time.Time { return time.Now().Add(10 * 24 * time.Hour) }
	if pulled := must[[]Path](t)(alice.Freshen(ctx, []Path{production}, time.Second)); len(pulled) != 0 {
		t.Fatalf("a copy in the first half of the limit was pulled: %v", pulled)
	}
	now = func() time.Time { return time.Now().Add(20 * 24 * time.Hour) }
	if pulled := must[[]Path](t)(alice.Freshen(ctx, []Path{production}, time.Second)); len(pulled) != 1 {
		t.Fatalf("a copy past half of the limit was not renewed: %v", pulled)
	}
	// Renewed, it lasts another 30 days from then.
	now = func() time.Time { return time.Now().Add(45 * 24 * time.Hour) }
	if _, _, err := alice.Values(production); err != nil {
		t.Fatalf("the renewed copy expired early: %v", err)
	}
}
