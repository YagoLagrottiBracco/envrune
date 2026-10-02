package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

func TestLinkLocalIsForOneDeveloper(t *testing.T) {
	f := newFixture(t, baseConfig)
	if err := f.session.Set("personal.my-database", []byte("postgres://mine")); err != nil {
		t.Fatal(err)
	}
	shared, _ := os.ReadFile(f.projectPath)
	if code := f.run("link", "DATABASE_URL", "personal.my-database", "--local"); code != 0 {
		t.Fatalf("link --local = %d: %s", code, f.output())
	}
	if !strings.Contains(f.output(), "for you only") || !strings.Contains(f.output(), "Added envrune.local.yml to .gitignore") {
		t.Fatalf("output = %s", f.output())
	}
	dir := filepath.Dir(f.projectPath)
	if after, _ := os.ReadFile(f.projectPath); string(after) != string(shared) {
		t.Fatalf("the shared file changed:\n%s", after)
	}
	if ignore, _ := os.ReadFile(filepath.Join(dir, ".gitignore")); !strings.Contains(string(ignore), project.LocalFileName) {
		t.Fatalf(".gitignore = %q", ignore)
	}
	config, err := project.Load(f.projectPath)
	if err != nil || config.Environments["development"]["DATABASE_URL"] != "personal.my-database" {
		t.Fatalf("development = %v, %v", config.Environments["development"], err)
	}
	// A second one does not add the line again.
	if code := f.run("link", "OTHER", "personal.my-database", "--local"); code != 0 || strings.Contains(f.output(), ".gitignore") {
		t.Fatalf("the second link = %d: %s", code, f.output())
	}
	if ignore, _ := os.ReadFile(filepath.Join(dir, ".gitignore")); strings.Count(string(ignore), project.LocalFileName) != 1 {
		t.Fatalf(".gitignore = %q", ignore)
	}
}
