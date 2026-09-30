package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

func TestDotenvEnvironmentNames(t *testing.T) {
	for name, want := range map[string]string{
		".env": "development", ".env.local": "development", ".env.production": "production",
		".env.production.local": "production", ".env.test": "test", ".envrc": "", "env": "",
	} {
		if got, _ := dotenvEnvironment(name, "development"); got != want {
			t.Fatalf("dotenvEnvironment(%q) = %q, want %q", name, got, want)
		}
	}
	if _, template := dotenvEnvironment(".env.example", "development"); !template {
		t.Fatal(".env.example is not treated as a template")
	}
}

func TestMigrateMovesDotenvFilesIntoTheVault(t *testing.T) {
	f := newFixture(t, baseConfig)
	parent := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(parent, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("api/.env", "DATABASE_URL=postgres://shared-db-value\nAPI_TOKEN=\"api-token-value\" # dev\nEMPTY=\n")
	write("api/.env.production", "API_TOKEN=api-prod-token-value\n")
	write("api/.env.example", "API_TOKEN=put-yours-here\n")
	write("web/.env.local", "export DATABASE_URL='postgres://shared-db-value'\nSESSION_SECRET=web-session-value\n")
	write("web/envrune.yml", "version: 1\nproject: storefront\ndefault_env: development\nenvironments:\n  development:\n    SESSION_SECRET: web.session\n")
	if err := f.session.Set("web.session", []byte("newer-vault-value")); err != nil {
		t.Fatal(err)
	}

	// Store the shared value once, apply the plan, delete the .env files.
	f.choices = []string{"", "y", "y"}
	if code := f.run("migrate", "--siblings", filepath.Join(parent, "api")); code != 0 {
		t.Fatalf("migrate = %d:\n%s", code, f.output())
	}
	out := f.output()
	for _, want := range []string{
		"DATABASE_URL                 development  → shared.database-url.development",
		".env.production → production: 1 variable",
		"SESSION_SECRET", "skipped: the vault holds another value",
		"Left alone: " + filepath.Join(parent, "api", ".env.example"),
		"Deleted the migrated .env files",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("migrate output misses %q:\n%s", want, out)
		}
	}
	for _, value := range []string{"shared-db-value", "api-token-value", "web-session-value", "newer-vault-value"} {
		if strings.Contains(out, value) {
			t.Fatalf("migrate printed a value:\n%s", out)
		}
	}

	api, err := project.Load(filepath.Join(parent, "api", "envrune.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if api.Project != "api" || api.Environments["development"]["DATABASE_URL"] != "shared.database-url.development" || api.Environments["production"]["API_TOKEN"] != "api.api-token.production" {
		t.Fatalf("api/envrune.yml = %+v", api.Environments)
	}
	if _, ok := api.Environments["development"]["EMPTY"]; ok {
		t.Fatal("an empty value was linked")
	}
	web, _ := project.Load(filepath.Join(parent, "web", "envrune.yml"))
	if web.Environments["development"]["DATABASE_URL"] != "shared.database-url.development" || web.Environments["development"]["SESSION_SECRET"] != "web.session" {
		t.Fatalf("web/envrune.yml = %+v", web.Environments)
	}
	value, err := f.session.Reveal("", "web.session")
	if err != nil || string(value) != "newer-vault-value" {
		t.Fatalf("migrate overwrote a newer vault value: %q, %v", value, err)
	}
	if value, _ := f.session.Reveal("", "shared.database-url.development"); string(value) != "postgres://shared-db-value" {
		t.Fatalf("shared value = %q", value)
	}
	ignore, _ := os.ReadFile(filepath.Join(parent, "api", ".gitignore"))
	if !strings.Contains(string(ignore), ".env.*") || !strings.Contains(string(ignore), "!.env.example") {
		t.Fatalf(".gitignore = %q", ignore)
	}
	for _, rel := range []string{"api/.env", "api/.env.production", "web/.env.local"} {
		if _, err := os.Stat(filepath.Join(parent, rel)); err == nil {
			t.Fatalf("%s was not deleted", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(parent, "api", ".env.example")); err != nil {
		t.Fatal("the template was deleted")
	}
}

func TestMigrateChangesNothingWithoutConfirmation(t *testing.T) {
	f := newFixture(t, baseConfig)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TOKEN=some-token-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.choices = []string{"n"}
	if code := f.run("migrate", dir); code != 0 || !strings.Contains(f.output(), "Nothing was changed") {
		t.Fatalf("migrate = %d:\n%s", code, f.output())
	}
	if _, err := os.Stat(filepath.Join(dir, "envrune.yml")); err == nil {
		t.Fatal("envrune.yml was written without confirmation")
	}
	if names, _ := f.session.List(); len(names) != 0 {
		t.Fatalf("the vault changed: %v", names)
	}
}
