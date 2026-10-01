package cloud

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

func TestOfflineCopiesExpireWhenTheOrganizationSaysSo(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	t.Cleanup(func() { now = time.Now })
	later := func(days int) { now = func() time.Time { return time.Now().Add(time.Duration(days) * 24 * time.Hour) } }

	// Off by default: a copy works however old it is.
	value(t, bob, production, "stripe-key")
	later(400)
	if _, _, err := bob.Values(production); err != nil {
		t.Fatalf("without a limit, an old copy was refused: %v", err)
	}

	later(0)
	if err := bob.SetOfflineDays(ctx, "acme", 30); err == nil {
		t.Fatal("a consumer set the offline limit")
	}
	if err := alice.SetOfflineDays(ctx, "acme", 366); err == nil {
		t.Fatal("a limit over a year was accepted")
	}
	ok(t, alice.SetOfflineDays(ctx, "acme", 30))
	if org := must[*Org](t)(alice.ShowOrg(ctx, "acme")); org.OfflineDays != 30 {
		t.Fatalf("the organization shows %d days", org.OfflineDays)
	}

	// Bob's device learns the limit when it next talks to the server, and
	// from then on refuses a copy older than it, until it pulls again.
	value(t, bob, production, "stripe-key")
	later(29)
	if _, _, err := bob.Values(production); err != nil {
		t.Fatalf("a copy within the limit was refused: %v", err)
	}
	later(31)
	_, _, err := bob.Values(production)
	if !errors.Is(err, ErrCopyExpired) || !strings.Contains(err.Error(), "envrune cloud pull acme/shop/production") {
		t.Fatalf("a copy past the limit: %v", err)
	}
	if got := value(t, bob, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("after pulling again bob read %q", got)
	}

	// Turning it off reaches devices the same way.
	ok(t, alice.SetOfflineDays(ctx, "acme", 0))
	value(t, bob, production, "stripe-key")
	later(400)
	if _, _, err := bob.Values(production); err != nil {
		t.Fatalf("with the limit off, an old copy was refused: %v", err)
	}
}
