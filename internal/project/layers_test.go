package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func refs(t *testing.T, c Config, environment string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, ref := range c.Environments[environment] {
		out[name] = ref.String()
	}
	return out
}

const layered = `version: 1
project: shop
environments:
  development:
    DATABASE_URL: shop.dev-database
    API_KEY: shop.dev-api-key
    LOG_LEVEL: shop.log-level
  staging:
    DATABASE_URL: shop.staging-database
  production:
    API_KEY: shop.live-api-key
extends:
  staging: development
  production: staging
`

func TestEnvironmentsBuildOnEachOther(t *testing.T) {
	p := write(t, filepath.Join(t.TempDir(), "envrune.yml"), layered)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	staging, production := refs(t, c, "staging"), refs(t, c, "production")
	if staging["DATABASE_URL"] != "shop.staging-database" || staging["API_KEY"] != "shop.dev-api-key" || len(staging) != 3 {
		t.Fatalf("staging = %v", staging)
	}
	if production["DATABASE_URL"] != "shop.staging-database" || production["API_KEY"] != "shop.live-api-key" || production["LOG_LEVEL"] != "shop.log-level" {
		t.Fatalf("production = %v", production)
	}
	if len(refs(t, c, "development")) != 3 {
		t.Fatalf("development = %v", refs(t, c, "development"))
	}

	for name, bad := range map[string]string{
		"a circle":          strings.Replace(layered, "production: staging", "production: staging\n  development: production", 1),
		"an unknown parent": strings.Replace(layered, "production: staging", "production: nowhere", 1),
		"an unknown child":  strings.Replace(layered, "production: staging", "nowhere: staging", 1),
	} {
		if _, err := Load(write(t, filepath.Join(t.TempDir(), "envrune.yml"), bad)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestThePersonalOverrideIsOnePersonsAndStaysOutOfTheSharedFile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, filepath.Join(dir, "envrune.yml"), layered)
	write(t, filepath.Join(dir, LocalFileName), "environments:\n  staging:\n    DATABASE_URL: personal.my-database\n    EXTRA: personal.extra\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if staging := refs(t, c, "staging"); staging["DATABASE_URL"] != "personal.my-database" || staging["EXTRA"] != "personal.extra" || staging["API_KEY"] != "shop.dev-api-key" {
		t.Fatalf("staging = %v", staging)
	}
	if production := refs(t, c, "production"); production["DATABASE_URL"] != "shop.staging-database" {
		t.Fatalf("the override reached an environment that extends staging: %v", production)
	}

	// Writing the shared file back keeps it as it was: nothing inherited is
	// copied down, and nothing personal is copied in.
	if err := UpdateAtomic(p, func(c *Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "personal.") || strings.Count(string(raw), "shop.dev-api-key") != 1 || !strings.Contains(string(raw), "shop.staging-database") {
		t.Fatalf("the shared file is now:\n%s", raw)
	}
	again, err := Load(p)
	if err != nil || refs(t, again, "production")["LOG_LEVEL"] != "shop.log-level" || again.Extends["staging"] != "development" {
		t.Fatalf("after writing it back: %v, %v", again.Extends, err)
	}

	for name, bad := range map[string]string{
		"another key":            "project: x\n",
		"an unknown environment": "environments:\n  nowhere:\n    A: a.b\n",
		"a value":                "environments:\n  staging:\n    A: Not A Reference\n",
	} {
		write(t, filepath.Join(dir, LocalFileName), bad)
		if _, err := Load(p); err == nil {
			t.Errorf("an override with %s was accepted", name)
		}
	}
}

func TestAPackageStartsFromItsWorkspace(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "envrune.yml"), "version: 1\nproject: shop\ncloud: acme/shop\nenvironments:\n  development:\n    DATABASE_URL: shop.dev-database\n    LOG_LEVEL: shop.log-level\n  production:\n    DATABASE_URL: shop.live-database\n")
	p := write(t, filepath.Join(dir, "api", "envrune.yml"), "version: 1\nproject: shop-api\nworkspace: ..\nenvironments:\n  development:\n    PORT: shop.api-port\n    LOG_LEVEL: shop.api-log-level\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	development := refs(t, c, "development")
	if development["DATABASE_URL"] != "shop.dev-database" || development["PORT"] != "shop.api-port" || development["LOG_LEVEL"] != "shop.api-log-level" {
		t.Fatalf("development = %v", development)
	}
	if refs(t, c, "production")["DATABASE_URL"] != "shop.live-database" || c.Cloud != "acme/shop" {
		t.Fatalf("production = %v, cloud %q", refs(t, c, "production"), c.Cloud)
	}
	// A binding added to the package lands in the package's file only.
	if err := SetBinding(p, "development", "API_KEY", "shop.api-key"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "shop.dev-database") || !strings.Contains(string(raw), "shop.api-key") {
		t.Fatalf("the package's file is now:\n%s", raw)
	}

	write(t, filepath.Join(dir, "envrune.yml"), "version: 1\nproject: shop\nworkspace: ..\nenvironments:\n  development: {}\n")
	if _, err := Load(p); err == nil {
		t.Fatal("a workspace root with a workspace of its own was accepted")
	}
	write(t, filepath.Join(dir, "api", "envrune.yml"), "version: 1\nproject: shop-api\nworkspace: /etc\nenvironments:\n  development: {}\n")
	if _, err := Load(p); err == nil {
		t.Fatal("an absolute workspace was accepted")
	}
}

func TestFilesRenderAndChecksAreRead(t *testing.T) {
	p := write(t, filepath.Join(t.TempDir(), "envrune.yml"), "version: 1\nproject: shop\nenvironments:\n  development:\n    TLS_KEY: shop.tls-key\n"+
		"files:\n  - TLS_KEY\nrender:\n  APP_CONFIG: config/app.yml.tmpl\nchecks:\n  database: pg_isready\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Files) != 1 || c.Files[0] != "TLS_KEY" || c.Render["APP_CONFIG"] != "config/app.yml.tmpl" || c.Checks["database"] != "pg_isready" {
		t.Fatalf("files %v, render %v, checks %v", c.Files, c.Render, c.Checks)
	}
	for name, bad := range map[string]string{
		"files that is not a list": "files:\n  TLS_KEY: x\n",
		"a file twice":             "files:\n  - TLS_KEY\n  - TLS_KEY\n",
		"a render name":            "render:\n  app-config: a.tmpl\n",
		"a check name":             "checks:\n  Bad Name: true\n",
	} {
		content := "version: 1\nproject: shop\nenvironments:\n  development: {}\n" + bad
		if _, err := Load(write(t, filepath.Join(t.TempDir(), "envrune.yml"), content)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSetLocalBindingWritesTheOverride(t *testing.T) {
	dir := t.TempDir()
	p := write(t, filepath.Join(dir, "envrune.yml"), layered)
	created, err := SetLocalBinding(p, "development", "DATABASE_URL", "personal.my-database")
	if err != nil || !created {
		t.Fatalf("created %v: %v", created, err)
	}
	created, err = SetLocalBinding(p, "staging", "EXTRA", "personal.extra")
	if err != nil || created {
		t.Fatalf("the second binding: created %v: %v", created, err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if refs(t, c, "development")["DATABASE_URL"] != "personal.my-database" || refs(t, c, "staging")["EXTRA"] != "personal.extra" {
		t.Fatalf("development %v, staging %v", refs(t, c, "development"), refs(t, c, "staging"))
	}
	shared, _ := os.ReadFile(p)
	if string(shared) != layered {
		t.Fatalf("the shared file changed:\n%s", shared)
	}
	if _, err := SetLocalBinding(p, "nowhere", "A", "a.b"); err == nil {
		t.Fatal("an override for an environment that does not exist was written")
	}
}
