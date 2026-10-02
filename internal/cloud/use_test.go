package cloud

import (
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

func uses(t *testing.T, s *Service) []AuditEntry {
	t.Helper()
	var out []AuditEntry
	for _, e := range must[*AuditExport](t)(s.Audit(ctx, "acme")).Entries {
		if e.Action == "secret.use" {
			out = append(out, e)
		}
	}
	return out
}

func TestUseIsNotedOfflineAndReportedWhenOnline(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	value(t, bob, production, "stripe-key")

	// Noting use touches only the vault.
	before := len(must[*AuditExport](t)(alice.Audit(ctx, "acme")).Entries)
	ok(t, bob.RecordUse(production, []string{"stripe-key"}))
	ok(t, bob.RecordUse(production, []string{"stripe-key", "db-url"}))
	ok(t, bob.RecordUse(production, nil))
	if after := len(must[*AuditExport](t)(alice.Audit(ctx, "acme")).Entries); after != before {
		t.Fatalf("noting use reached the server: %d entries, then %d", before, after)
	}

	// The next moment online reports it, once.
	must[[]Path](t)(bob.Freshen(ctx, []Path{production}, time.Second))
	reported := uses(t, alice)
	if len(reported) != 2 || !strings.Contains(reported[1].DetailText, `"db-url"`) || !strings.Contains(reported[0].DetailText, "reported_by_device") {
		t.Fatalf("the audit log has %+v", reported)
	}
	if n := must[int](t)(bob.ReportUse(ctx)); n != 0 {
		t.Fatalf("use was reported twice: %d", n)
	}

	// A server out of reach keeps the notes for later.
	ok(t, bob.RecordUse(production, []string{"stripe-key"}))
	f.srv.Close()
	if _, err := bob.ReportUse(ctx); err == nil {
		t.Fatal("reporting to a server out of reach succeeded")
	}
	if st := must[*State](t)(bob.state()); len(st.Use) != 1 {
		t.Fatalf("the device kept %d notes", len(st.Use))
	}
}

func TestNotesOfUseAreBounded(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	for range maxPendingUse + 20 {
		ok(t, alice.RecordUse(production, []string{"stripe-key"}))
	}
	if st := must[*State](t)(alice.state()); len(st.Use) != maxPendingUse {
		t.Fatalf("the device keeps %d notes", len(st.Use))
	}
}
