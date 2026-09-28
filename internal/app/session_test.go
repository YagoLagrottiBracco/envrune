package app

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/project"
)

func TestSessionReusesOpenedVaultAndCloses(t *testing.T) {
	path, password := initializedVault(t)
	session, err := OpenSession(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Set("openai.demo", []byte("session-only-sentinel")); err != nil {
		t.Fatal(err)
	}
	refs, err := session.List()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refs, []string{"openai.demo"}) {
		t.Fatalf("List() = %v", refs)
	}
	session.Close()

	refs, err = (VaultService{}).List(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refs, []string{"openai.demo"}) {
		t.Fatalf("stored references after close = %v", refs)
	}
}

func TestSessionLinkAndResolveEnvironment(t *testing.T) {
	path, password := initializedVault(t)
	projectPath := filepath.Join(t.TempDir(), "envrune.yml")
	if err := project.WriteAtomic(projectPath, project.Config{Version: 1, Project: "session", Environments: map[string]map[string]domain.Reference{}}); err != nil {
		t.Fatal(err)
	}
	session, err := OpenSession(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Set("openai.demo", []byte("session-secret-sentinel")); err != nil {
		t.Fatal(err)
	}
	if err := session.Link(projectPath, "dev", "OPENAI_API_KEY", "openai.demo"); err != nil {
		t.Fatal(err)
	}
	pairs, err := session.ResolveEnvironment(projectPath, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 || pairs[0].Name != "OPENAI_API_KEY" || string(pairs[0].Value) != "session-secret-sentinel" {
		t.Fatalf("ResolveEnvironment() = %#v", pairs)
	}
}
