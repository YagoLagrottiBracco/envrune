package cloud

import (
	"slices"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// second sets up another device of an existing user and has first approve it.
func second(t *testing.T, f *fakeServer, first *Service, user, name string) (*Service, string) {
	t.Helper()
	s := f.signIn(user)
	pending := must[*SetupResult](t)(s.Setup(ctx, name))
	id := must[*Status](t)(s.Status()).DeviceID
	must[int](t)(first.ApproveDevice(ctx, id, pending.DeviceFingerprint))
	must[*SetupResult](t)(s.Setup(ctx, name))
	return s, id
}

func TestALostDeviceIsCutOffAndWhatItKnewIsListed(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	ok(t, alice.CreateEnvironment(ctx, "acme", "shop", "staging"))
	laptop, laptopID := second(t, f, alice, "alice", "alice-travel")
	if got := value(t, laptop, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("the second device read %q", got)
	}

	h := must[*Handover](t)(alice.RevokeDevice(ctx, laptopID))
	// It had been given the keys of both environments; both get a new one.
	slices.Sort(h.Rotated)
	if !slices.Equal(h.Rotated, []string{"acme/shop/production", "acme/shop/staging"}) || len(h.Left) != 0 {
		t.Fatalf("the revocation handed over %+v", h)
	}
	if _, err := laptop.Pull(ctx, production, false); err == nil {
		t.Fatal("a revoked device pulled")
	}
	// It fetched production only, so only that value may be known.
	tasks := must[[]RotationTask](t)(alice.Rotation(ctx, "acme"))
	if len(tasks) != 1 || tasks[0].Reason != "device revoked" || tasks[0].Subject != "alice ("+laptopID+")" || tasks[0].Pending() != 1 {
		t.Fatalf("the rotation is %+v", tasks)
	}
	if got := value(t, alice, production, "stripe-key"); got != "sk_live_1" {
		t.Fatalf("alice read %q after the revocation", got)
	}
	if _, err := alice.RevokeDevice(ctx, must[*Status](t)(alice.Status()).DeviceID); err == nil {
		t.Fatal("the device in use was revoked from itself")
	}
}

func TestRevokingADeviceLeavesWhatItsOwnerDoesNotAdminister(t *testing.T) {
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	phone, phoneID := second(t, f, bob, "bob", "bob-phone")
	value(t, phone, production, "stripe-key")

	h := must[*Handover](t)(bob.RevokeDevice(ctx, phoneID))
	if len(h.Rotated) != 0 || !slices.Equal(h.Left, []string{"acme/shop/production"}) {
		t.Fatalf("a consumer's revocation handed over %+v", h)
	}
	// An administrator finishes it, and sees what the device fetched.
	must[uint64](t)(alice.Rotate(ctx, "acme", "shop", "production", false))
	if tasks := must[[]RotationTask](t)(alice.Rotation(ctx, "acme")); len(tasks) != 1 || tasks[0].Pending() != 1 {
		t.Fatalf("the rotation is %+v", tasks)
	}
}
