package app

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	crypto "github.com/envrune/envrune/internal/crypto"
	"github.com/envrune/envrune/internal/vault"
)

func TestLinkAndUsageReadCurrentProjectConfiguration(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault.ev1")
	projectPath := filepath.Join(root, "envrune.yml")
	password := []byte("correct horse battery staple")
	if err := vault.Create(vaultPath, password, crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectPath, []byte("version: 1\nproject: x\nenvironments: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := VaultService{}
	if err := s.Link(vaultPath, projectPath, "dev", "OPENAI_API_KEY", "openai.personal", password); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectPath, []byte("version: 1\nproject: x\nenvironments:\n  prod:\n    OPENAI_API_KEY: openai.personal\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := s.Usage(vaultPath, "openai.personal", password)
	if err != nil {
		t.Fatal(err)
	}
	want := []Usage{{ProjectPath: projectPath, Environment: "prod", Variable: "OPENAI_API_KEY"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Usage() = %#v, want %#v", got, want)
	}
}

func TestLinkWrongPasswordDoesNotModifyProject(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault.ev1")
	projectPath := filepath.Join(root, "envrune.yml")
	password := []byte("correct horse battery staple")
	if err := vault.Create(vaultPath, password, crypto.DefaultKDFParams(1)); err != nil {
		t.Fatal(err)
	}
	initial := []byte("version: 1\nproject: x\nenvironments: {}\n")
	if err := os.WriteFile(projectPath, initial, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (VaultService{}).Link(vaultPath, projectPath, "dev", "OPENAI_API_KEY", "openai.personal", []byte("wrong")); err == nil {
		t.Fatal("expected error")
	}
	after, err := os.ReadFile(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(initial) {
		t.Fatal("link modified project after vault authentication failed")
	}
}
