package app

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestVaultServiceInitSetAndList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.ev1")
	s := VaultService{}
	password := []byte("correct horse battery staple")
	if err := s.Init(p, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(p, password, "openai.personal", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(p, password)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"openai.personal"}) {
		t.Fatalf("List() = %v", got)
	}
}
