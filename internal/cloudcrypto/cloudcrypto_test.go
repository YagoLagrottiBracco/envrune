package cloudcrypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// org is a small organization: alice founded it (the root), bob is an admin
// for the shop project, carol a maintainer and dave a consumer of
// shop/production, erin an auditor. eve is not a member: she stands for a
// server that tries to insert keys of its own.
type org struct {
	trust                               Trust
	certs                               []*MembershipCertificate
	alice, bob, carol, dave, erin, eve  *Account
	aliceDev, carolDev, daveDev, eveDev *Device
}

// must fails the test through a panic, which Go reports with the stack.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func newOrg(t *testing.T) *org {
	t.Helper()
	o := &org{}
	for _, a := range []struct {
		p  **Account
		id string
	}{{&o.alice, "alice"}, {&o.bob, "bob"}, {&o.carol, "carol"}, {&o.dave, "dave"}, {&o.erin, "erin"}, {&o.eve, "eve"}} {
		*a.p = must(NewAccount(a.id))
	}
	o.trust = Trust{OrgID: "acme", Roots: map[string]ed25519.PublicKey{"alice": o.alice.Public}}
	o.certs = []*MembershipCertificate{
		must(o.alice.Certify("acme", "bob", o.bob.Public, RoleAdmin, []string{"shop/*"})),
		must(o.bob.Certify("acme", "carol", o.carol.Public, RoleMaintainer, []string{"shop/production"})),
		must(o.bob.Certify("acme", "dave", o.dave.Public, RoleConsumer, []string{"shop/production"})),
		must(o.bob.Certify("acme", "erin", o.erin.Public, RoleAuditor, []string{"shop/*"})),
	}
	o.aliceDev = must(NewDevice("alice", "alice-laptop"))
	o.carolDev = must(NewDevice("carol", "carol-laptop"))
	o.daveDev = must(NewDevice("dave", "dave-laptop"))
	o.eveDev = must(NewDevice("eve", "eve-server"))
	return o
}

func deviceCert(a *Account, d *Device) *RecipientCertificate {
	return a.CertifyDevice(d.DeviceID, d.Identity.Recipient().String(), d.SigningPublic())
}

func TestMessagesAreUnambiguous(t *testing.T) {
	if bytes.Equal(message("a", []byte("bc")), message("a", []byte("b"), []byte("c"))) {
		t.Fatal("different fields share an encoding")
	}
	if bytes.Equal(message("ab", []byte("c")), message("a", []byte("bc"))) {
		t.Fatal("label and fields share an encoding")
	}
}

func TestRecoveryBackupRestoresTheAccount(t *testing.T) {
	key := must(NewRecoveryKey())
	account := must(NewAccount("alice"))
	identity := must(age.GenerateX25519Identity())
	sealed := must(SealRecoveryBackup(key, account, identity))
	restored := must(OpenRecoveryBackup(key, "alice", sealed))
	if !restored.Account.Public.Equal(account.Public) || restored.Identity.String() != identity.String() {
		t.Fatal("the backup did not restore the same keys")
	}
	other := must(NewRecoveryKey())
	if _, err := OpenRecoveryBackup(other, "alice", sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another recovery key opened the backup: %v", err)
	}
	if _, err := OpenRecoveryBackup(key, "mallory", sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("the backup opened for another user: %v", err)
	}
}

func TestMembershipChainsToTheRoot(t *testing.T) {
	o := newOrg(t)
	carol := must(o.trust.Verify(o.certs, "carol"))
	if carol.Role != RoleMaintainer || !carol.CanAdminister("shop", "production") || carol.CanUse("shop", "staging") {
		t.Fatalf("carol = %+v", carol)
	}
	if dave := must(o.trust.Verify(o.certs, "dave")); !dave.CanUse("shop", "production") || dave.CanAdminister("shop", "production") {
		t.Fatalf("dave = %+v", dave)
	}
	if erin := must(o.trust.Verify(o.certs, "erin")); erin.CanUse("shop", "production") {
		t.Fatal("an auditor may use an environment")
	}

	forged := []*MembershipCertificate{
		// The server signs a membership for its own key.
		must(o.eve.Certify("acme", "eve", o.eve.Public, RoleOwner, []string{"*"})),
		// An admin makes someone an owner.
		must(o.bob.Certify("acme", "eve", o.eve.Public, RoleOwner, []string{"*"})),
		// An admin grants beyond their own scope.
		must(o.bob.Certify("acme", "eve", o.eve.Public, RoleConsumer, []string{"billing/*"})),
		// A consumer adds a member.
		must(o.dave.Certify("acme", "eve", o.eve.Public, RoleConsumer, []string{"shop/production"})),
		// A certificate for another organization.
		must(o.alice.Certify("other-org", "eve", o.eve.Public, RoleConsumer, []string{"*"})),
	}
	for i, c := range forged {
		if _, err := o.trust.Verify(append(o.certs, c), "eve"); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("forged certificate %d was accepted: %v", i, err)
		}
	}
	tampered := *o.certs[1]
	tampered.Role = RoleOwner
	if _, err := o.trust.Verify([]*MembershipCertificate{o.certs[0], &tampered}, "carol"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a tampered certificate was accepted: %v", err)
	}
}

func TestRemovalTakesEffectAndOutranksOlderCertificates(t *testing.T) {
	o := newOrg(t)
	time.Sleep(time.Millisecond) // removal is issued after the membership
	removal := must(o.bob.Certify("acme", "dave", o.dave.Public, RoleRemoved, []string{"shop/production"}))
	if _, err := o.trust.Verify(append(o.certs, removal), "dave"); err == nil {
		t.Fatal("a removed member is still a member")
	}
}

func TestServerCannotAddARecipientOfItsOwn(t *testing.T) {
	o := newOrg(t)
	if err := o.trust.VerifyRecipient(o.certs, deviceCert(o.carol, o.carolDev), "shop", "production"); err != nil {
		t.Fatalf("carol's device was rejected: %v", err)
	}
	// eve's device, certified by eve, who is not a member.
	if err := o.trust.VerifyRecipient(o.certs, deviceCert(o.eve, o.eveDev), "shop", "production"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a non-member's device was accepted: %v", err)
	}
	// eve's device presented as carol's, signed with eve's key.
	impostor := deviceCert(o.eve, o.eveDev)
	impostor.UserID = "carol"
	if err := o.trust.VerifyRecipient(o.certs, impostor, "shop", "production"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a device claiming to be carol's was accepted: %v", err)
	}
	// carol's real certificate with eve's recipient swapped in.
	swapped := deviceCert(o.carol, o.carolDev)
	swapped.AgeRecipient = o.eveDev.Identity.Recipient().String()
	if err := o.trust.VerifyRecipient(o.certs, swapped, "shop", "production"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a swapped recipient was accepted: %v", err)
	}
	// An auditor's device never receives the key.
	erinDev := must(NewDevice("erin", "erin-laptop"))
	if err := o.trust.VerifyRecipient(o.certs, deviceCert(o.erin, erinDev), "shop", "production"); err == nil {
		t.Fatal("an auditor's device was accepted")
	}
}

func TestMachineTokensStayInTheirScope(t *testing.T) {
	o := newOrg(t)
	token := must(NewMachineToken())
	cert := o.bob.CertifyMachine(token.ID, token.Identity.Recipient().String(), []string{"shop/production"})
	if err := o.trust.VerifyRecipient(o.certs, cert, "shop", "production"); err != nil {
		t.Fatalf("the token was rejected: %v", err)
	}
	if err := o.trust.VerifyRecipient(o.certs, cert, "shop", "staging"); err == nil {
		t.Fatal("the token was accepted outside its scope")
	}
	byConsumer := o.dave.CertifyMachine(token.ID, token.Identity.Recipient().String(), []string{"shop/production"})
	if err := o.trust.VerifyRecipient(o.certs, byConsumer, "shop", "production"); err == nil {
		t.Fatal("a consumer created a machine token")
	}

	parsed := must(ParseMachineToken(token.String()))
	if parsed.ID != token.ID || !TokenSecretMatches(parsed.Secret, token.SecretHash()) || parsed.Identity.String() != token.Identity.String() {
		t.Fatal("the token did not round-trip")
	}
	if TokenSecretMatches([]byte("wrong"), token.SecretHash()) {
		t.Fatal("a wrong secret matched")
	}
	for _, bad := range []string{"", "envrune_mt_", "envrune_mt_id.secret", "other_" + token.String()[len(tokenPrefix):]} {
		if _, err := ParseMachineToken(bad); err == nil {
			t.Fatalf("ParseMachineToken(%q) succeeded", bad)
		}
	}
}

func TestWrappedKeysOpenOnlyWithTheRightIdentityAndSignature(t *testing.T) {
	o := newOrg(t)
	k := must(NewEnvironmentKey("acme", "shop", "production", 1))
	wrapped := must(o.aliceDev.Wrap(k, deviceCert(o.carol, o.carolDev)))
	got := must(Unwrap(wrapped, o.carolDev.Identity, o.aliceDev.SigningPublic()))
	if !bytes.Equal(got.Key, k.Key) || got.Epoch != 1 {
		t.Fatal("the unwrapped key differs")
	}
	if _, err := Unwrap(wrapped, o.daveDev.Identity, o.aliceDev.SigningPublic()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another device unwrapped the key: %v", err)
	}
	if _, err := Unwrap(wrapped, o.carolDev.Identity, o.eveDev.SigningPublic()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a key wrapped by someone else was accepted: %v", err)
	}
	// The server relabels a key as another environment's.
	moved := *wrapped
	moved.EnvironmentID = "staging"
	if _, err := Unwrap(&moved, o.carolDev.Identity, o.aliceDev.SigningPublic()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a relabeled key was accepted: %v", err)
	}
	// The server substitutes a key it wrapped itself.
	evil := must(NewEnvironmentKey("acme", "shop", "production", 1))
	substituted := must(o.eveDev.Wrap(evil, deviceCert(o.carol, o.carolDev)))
	substituted.WrapperUserID, substituted.WrapperDeviceID, substituted.Signature = wrapped.WrapperUserID, wrapped.WrapperDeviceID, wrapped.Signature
	if _, err := Unwrap(substituted, o.carolDev.Identity, o.aliceDev.SigningPublic()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a substituted key was accepted: %v", err)
	}
}

func TestSealedValuesCannotBeMovedOrForged(t *testing.T) {
	o := newOrg(t)
	k := must(NewEnvironmentKey("acme", "shop", "production", 3))
	record := must(o.carolDev.Seal(k, "stripe-key", 7, []byte("sk_live_cloud_value")))
	value := must(Open(record, k, o.carolDev.SigningPublic()))
	if string(value) != "sk_live_cloud_value" {
		t.Fatalf("Open() = %q", value)
	}
	if bytes.Contains(record.Ciphertext, []byte("cloud_value")) {
		t.Fatal("the ciphertext contains the value")
	}

	// The server moves the ciphertext elsewhere and re-signs nothing: every
	// field is covered by the writer's signature.
	for name, change := range map[string]func(r *SecretRecord){
		"name":        func(r *SecretRecord) { r.Name = "db-password" },
		"version":     func(r *SecretRecord) { r.Version = 8 },
		"environment": func(r *SecretRecord) { r.EnvironmentID = "staging" },
		"ciphertext":  func(r *SecretRecord) { r.Ciphertext[0] ^= 1 },
		"writer":      func(r *SecretRecord) { r.WriterDeviceID = "dave-laptop" },
	} {
		moved := *record
		moved.Ciphertext = append([]byte(nil), record.Ciphertext...)
		change(&moved)
		if _, err := Open(&moved, k, o.carolDev.SigningPublic()); err == nil {
			t.Fatalf("a record with a changed %s was accepted", name)
		}
	}
	// Even with a matching signature, the associated data stops a
	// ciphertext from being opened as another secret.
	relabeled := *record
	relabeled.Name = "db-password"
	relabeled.Signature = o.carolDev.sign(relabeled.signed())
	if _, err := Open(&relabeled, k, o.carolDev.SigningPublic()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a relabeled ciphertext decrypted: %v", err)
	}
	// A record claiming to be carol's, signed by someone else.
	if _, err := Open(record, k, o.daveDev.SigningPublic()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("the wrong writer key verified: %v", err)
	}
}

func TestRemovedMemberCannotReadTheNextEpoch(t *testing.T) {
	o := newOrg(t)
	old := must(NewEnvironmentKey("acme", "shop", "production", 1))
	next := must(NewEnvironmentKey("acme", "shop", "production", 2))
	record := must(o.carolDev.Seal(next, "stripe-key", 2, []byte("rotated-value")))
	if _, err := Open(record, old, o.carolDev.SigningPublic()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("an old epoch key opened a new value: %v", err)
	}
	stale := *old
	stale.Epoch = 2 // pretending does not help: the key is different
	if _, err := Open(record, &stale, o.carolDev.SigningPublic()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a relabeled old key opened a new value: %v", err)
	}
}

func TestVersionsDetectRollback(t *testing.T) {
	var v Versions
	r := &SecretRecord{OrgID: "acme", ProjectID: "shop", EnvironmentID: "production", Name: "stripe-key", Version: 5, Epoch: 2}
	if err := v.Accept(r); err != nil {
		t.Fatal(err)
	}
	older := *r
	older.Version = 4
	if err := v.Accept(&older); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older version was accepted: %v", err)
	}
	oldEpoch := *r
	oldEpoch.Version, oldEpoch.Epoch = 6, 1
	if err := v.Accept(&oldEpoch); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older epoch was accepted: %v", err)
	}
	newer := *r
	newer.Version = 6
	if err := v.Accept(&newer); err != nil {
		t.Fatalf("a newer version was rejected: %v", err)
	}
}

func TestFingerprintsAreStableAndDistinct(t *testing.T) {
	a := Fingerprint([]byte("key one"))
	if a != Fingerprint([]byte("key one")) || a == Fingerprint([]byte("key two")) {
		t.Fatal("fingerprints are not stable and distinct")
	}
	if len(strings.Split(a, "-")) != 6 {
		t.Fatalf("fingerprint %q does not have 6 groups", a)
	}
}
