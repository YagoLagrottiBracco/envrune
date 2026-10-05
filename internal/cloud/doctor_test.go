package cloud

import (
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// said reports whether a check at level contains text.
func said(checks []Check, level CheckLevel, text string) bool {
	for _, c := range checks {
		if c.Level == level && strings.Contains(c.Message, text) {
			return true
		}
	}
	return false
}

func worst(checks []Check) CheckLevel {
	level := CheckOK
	for _, c := range checks {
		level = max(level, c.Level)
	}
	return level
}

func TestDoctorFindsNothingWrongWithAWorkingSetup(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)

	checks := alice.Doctor(ctx)
	if worst(checks) != CheckOK {
		t.Fatalf("a working setup has findings: %+v", checks)
	}
	for _, want := range []string{"answers", "database has the schema", "signed in as alice@example.com", "this device is trusted",
		"recovery key's recipient on the server is signed", "organization acme: you are owner"} {
		if !said(checks, CheckOK, want) {
			t.Errorf("no check says %q: %+v", want, checks)
		}
	}
}

func TestDoctorNamesWhatIsWrongInTheOrderItMatters(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)

	// A server whose database was not migrated: said before anything else.
	f.mu.Lock()
	f.database = DatabaseBehind
	f.mu.Unlock()
	if checks := alice.Doctor(ctx); !said(checks, CheckFail, "database is behind the server") || !said(checks, CheckFail, "cloud/supabase/migrations") {
		t.Fatalf("a database that is behind: %+v", checks)
	}
	f.mu.Lock()
	f.database = DatabaseOK
	f.mu.Unlock()

	// A second device, before and after approval.
	second := f.signIn("alice")
	if checks := second.Doctor(ctx); !said(checks, CheckWarn, "not set up; run `envrune cloud init`") {
		t.Fatalf("a device that never ran init: %+v", checks)
	}
	must[*SetupResult](t)(second.Setup(ctx, "desktop"))
	if checks := second.Doctor(ctx); !said(checks, CheckWarn, "waiting for approval") || said(checks, CheckOK, "acme") {
		t.Fatalf("a pending device: %+v", checks)
	}

	// An account that is in no organization and has no device.
	if checks := f.signIn("zoe").Doctor(ctx); !said(checks, CheckWarn, "no keys yet; run `envrune cloud init`") {
		t.Fatalf("a new account: %+v", checks)
	}

	// A recovery recipient the account key did not sign, as a server that
	// replaced it would present.
	f.mu.Lock()
	for _, d := range f.devices {
		if d.UserID == "alice" && d.Kind == cloudcrypto.KindRecovery {
			d.AgeRecipient = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
		}
	}
	f.mu.Unlock()
	if checks := alice.Doctor(ctx); !said(checks, CheckFail, "recovery recipient is not signed by your account key") {
		t.Fatalf("a replaced recovery recipient: %+v", checks)
	}

	// An environment waiting for a new key.
	f.mu.Lock()
	for _, e := range f.envs {
		e.needsRotation = true
	}
	f.mu.Unlock()
	if checks := alice.Doctor(ctx); !said(checks, CheckWarn, "environment acme/shop/production waits for a new key; run `envrune cloud rotate acme/shop/production`") {
		t.Fatalf("an environment that needs rotation: %+v", checks)
	}

	// Signed out.
	ok(t, alice.Logout())
	if checks := alice.Doctor(ctx); worst(checks) != CheckFail || !said(checks, CheckFail, "envrune login") {
		t.Fatalf("signed out: %+v", checks)
	}
}
