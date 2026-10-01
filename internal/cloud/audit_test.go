package cloud

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// The hashes were computed apart from this package, from the formula of the
// database trigger: sha256(prev || fields joined by 0x1f), absent actors
// skipped, the time in UTC with six decimals.
func TestAuditHashMatchesTheDatabaseFormula(t *testing.T) {
	user, device, token := "7a1f2c3d-0000-4000-8000-000000000001", "alice-laptop", "tok_1"
	previous := make([]byte, 32)
	for i := range previous {
		previous[i] = byte(i)
	}
	for _, c := range []struct {
		entry AuditEntry
		want  string
	}{
		{AuditEntry{OrgID: "0b6f8f0e-3a0c-4c38-9a61-6f0c2f3f1a11", At: "2026-09-30T22:47:26.71+00:00", ActorUserID: &user, ActorDeviceID: &device,
			Action: "secret.write", Target: "shop/production/stripe-key", DetailText: `{"epoch": 2, "version": 3}`, PrevHash: previous},
			"85f19561fb19d889b8ea7217e57ca73ca0adb32558c415ecd7b782b7106e20e3"},
		{AuditEntry{OrgID: "0b6f8f0e-3a0c-4c38-9a61-6f0c2f3f1a11", At: "2026-09-30T19:47:26.000001-03:00", ActorTokenID: &token,
			Action: "environment.fetch", Target: "shop/production", DetailText: `{"epoch": 1}`},
			"698b309b88a184ae63b38f139d7b4d1a271572b7d1e673ddeff6543b1199cef1"},
	} {
		got := must[[]byte](t)(c.entry.hash())
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%s hashed to %x", c.entry.Action, got)
		}
	}
}

func TestAuditLogVerifiesAndStaysTheSameLog(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	value(t, bob, production, "stripe-key")

	first := must[*AuditExport](t)(alice.Audit(ctx, "acme"))
	if len(first.Entries) < 4 || first.Previous != nil || first.Head.ID != first.Entries[len(first.Entries)-1].ID {
		t.Fatalf("the first export: %d entries, head %s, previous %v", len(first.Entries), first.Head, first.Previous)
	}
	if _, err := bob.Audit(ctx, "acme"); err == nil {
		t.Fatal("a consumer read the audit log")
	}

	// An export is a file that verifies again, and a later one continues it.
	var file bytes.Buffer
	ok(t, WriteAudit(&file, first.Entries))
	saved := must[[]AuditEntry](t)(ReadAudit(&file))
	if head := must[AuditHead](t)(VerifyAudit(saved)); head.ID != first.Head.ID {
		t.Fatalf("the file's head is %s", head)
	}
	value(t, alice, production, "stripe-key")
	second := must[*AuditExport](t)(alice.Audit(ctx, "acme"))
	if second.Previous == nil || second.Previous.ID != first.Head.ID || len(second.Entries) <= len(first.Entries) {
		t.Fatalf("the second export: %d entries, previous %v", len(second.Entries), second.Previous)
	}
	ok(t, AuditContinues(saved, second.Entries))
	if err := AuditContinues(second.Entries, saved); !errors.Is(err, ErrAuditRewritten) {
		t.Fatalf("a shorter log continued a longer one: %v", err)
	}
}

func TestAuditLogChangesAreFound(t *testing.T) {
	export := func(change func(log []AuditEntry) []AuditEntry, rechain bool) error {
		f := newFakeServer(t)
		alice, _ := founder(t, f)
		value(t, alice, production, "stripe-key")
		must[*AuditExport](t)(alice.Audit(ctx, "acme"))
		value(t, alice, production, "stripe-key")
		f.mu.Lock()
		f.audits["org-acme"] = change(f.audits["org-acme"])
		if rechain {
			f.rechain("org-acme")
		}
		f.mu.Unlock()
		_, err := alice.Audit(ctx, "acme")
		return err
	}
	if err := export(func(log []AuditEntry) []AuditEntry { return log }, true); err != nil {
		t.Fatalf("an untouched log: %v", err)
	}

	// Edits and gaps break the chain.
	for name, change := range map[string]func([]AuditEntry) []AuditEntry{
		"an edited target": func(log []AuditEntry) []AuditEntry { log[1].Target = "nothing"; return log },
		"an edited actor":  func(log []AuditEntry) []AuditEntry { mallory := "mallory"; log[1].ActorUserID = &mallory; return log },
		"an edited time":   func(log []AuditEntry) []AuditEntry { log[1].At = "2020-01-01T00:00:00+00:00"; return log },
		"another detail shown": func(log []AuditEntry) []AuditEntry {
			log[len(log)-1].Detail = json.RawMessage(`{"epoch": 9}`)
			return log
		},
		"a removed entry": func(log []AuditEntry) []AuditEntry { return append(log[:1], log[2:]...) },
		"a missing start": func(log []AuditEntry) []AuditEntry { return log[1:] },
	} {
		if err := export(change, false); !errors.Is(err, ErrAuditBroken) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A server that rewrites the whole chain, or cuts its end, gives a log
	// that verifies alone but not against what this device saw before.
	for name, change := range map[string]func([]AuditEntry) []AuditEntry{
		"a rewritten log": func(log []AuditEntry) []AuditEntry { return append(log[:1], log[2:]...) },
		"a rewritten entry": func(log []AuditEntry) []AuditEntry {
			log[0].Target = "nothing"
			return log
		},
		"a cut end": func(log []AuditEntry) []AuditEntry { return log[:2] },
	} {
		if err := export(change, true); !errors.Is(err, ErrAuditRewritten) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
