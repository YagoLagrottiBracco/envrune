package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetCloudKeepsCommentsAndOtherSections(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	before := "# The shop.\nversion: 1\nproject: shop\ndefault_env: dev\nenvironments:\n  dev:\n    API_KEY: team.api-key # shared\n"
	if err := os.WriteFile(p, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SetCloud(p, "acme/shop"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	want := "# The shop.\nversion: 1\nproject: shop\ncloud: acme/shop\ndefault_env: dev\nenvironments:\n  dev:\n    API_KEY: team.api-key # shared\n"
	if string(raw) != want {
		t.Fatalf("envrune.yml is now:\n%s", raw)
	}
	if err := SetCloud(p, "acme/other"); err != nil {
		t.Fatal(err)
	}
	if config, err := Load(p); err != nil || config.Cloud != "acme/other" {
		t.Fatalf("after changing the link: %q, %v", config.Cloud, err)
	}
	if raw, _ := os.ReadFile(p); strings.Count(string(raw), "cloud:") != 1 {
		t.Fatalf("the link was added twice:\n%s", raw)
	}
	if err := SetCloud(p, "not a link"); err == nil {
		t.Fatal("an invalid link was accepted")
	}
}
