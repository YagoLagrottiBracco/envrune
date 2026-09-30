package team

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTeamFileSharesSecretsOnlyWithMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	alice, _ := NewIdentity()
	bob, _ := NewIdentity()
	eve, _ := NewIdentity()
	file, err := Create(path, "alice", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Set("team.stripe.test", []byte("sk_test_sentinel")); err != nil {
		t.Fatal(err)
	}
	if err := file.Set("personal.key", []byte("x")); !errors.Is(err, ErrNotTeamRef) {
		t.Fatalf("Set() without team prefix = %v", err)
	}
	bobPublic, _ := PublicKey(bob)
	if err := file.AddMember("bob", bobPublic); err != nil {
		t.Fatal(err)
	}
	if err := file.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "sk_test_sentinel") {
		t.Fatal("team file leaked a value")
	}
	opened, err := Open(path, bob)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := opened.Value("team.stripe.test"); !ok || string(value) != "sk_test_sentinel" {
		t.Fatalf("bob read %q, %v", value, ok)
	}
	if _, err := Open(path, eve); !errors.Is(err, ErrNotRecipient) {
		t.Fatalf("Open() by a non-member = %v", err)
	}
	if err := opened.RemoveMember("bob"); err != nil {
		t.Fatal(err)
	}
	if err := opened.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, bob); !errors.Is(err, ErrNotRecipient) {
		t.Fatalf("removed member could still open the file: %v", err)
	}
	if _, err := Open(path, alice); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedMemberListIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	alice, _ := NewIdentity()
	if _, err := Create(path, "alice", alice); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), `"name": "alice"`, `"name": "mallory"`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, alice); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("Open() of a tampered file = %v", err)
	}
}
