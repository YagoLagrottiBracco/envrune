package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

func TestCloudNamesForTeamReferences(t *testing.T) {
	names, err := cloudNames([]string{"team.stripe-key", "team.db.url"})
	if err != nil || names["team.stripe-key"] != "stripe-key" || names["team.db.url"] != "db-url" {
		t.Fatalf("names = %v, %v", names, err)
	}
	if _, err := cloudNames([]string{"team.db-url", "team.db.url"}); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("two references with one cloud name: %v", err)
	}
	if _, err := cloudNames([]string{"team.9lives"}); err == nil {
		t.Fatal("a name the cloud does not allow was accepted")
	}
}

func TestRelinkPointsTeamVariablesAtTheCloud(t *testing.T) {
	target := cloud.Path{Org: "acme", Project: "shop", Env: "production"}
	names := map[string]string{"team.stripe.key": "stripe-key"}
	write := func(config string) string {
		p := filepath.Join(t.TempDir(), "envrune.yml")
		if err := os.WriteFile(p, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	p := write("version: 1\nproject: shop\nenvironments:\n  production:\n    STRIPE_KEY: team.stripe.key # shared\n    LOCAL: personal.local\n  staging:\n    STRIPE_KEY: team.stripe.key\n")
	changed, skipped, err := relinkTeam(p, target, names)
	if err != nil || len(changed) != 2 || len(skipped) != 0 {
		t.Fatalf("relink = %v, %v, %v", changed, skipped, err)
	}
	config, err := project.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	// The environment of the same name reads the short form; another one
	// names the secret in full; what was not imported is untouched.
	if config.Cloud != "acme/shop" || config.Environments["production"]["STRIPE_KEY"] != "cloud.stripe-key" ||
		config.Environments["staging"]["STRIPE_KEY"] != "cloud.acme.shop.production.stripe-key" || config.Environments["production"]["LOCAL"] != "personal.local" {
		t.Fatalf("envrune.yml is now %+v", config)
	}
	if raw, _ := os.ReadFile(p); !strings.Contains(string(raw), "# shared") {
		t.Fatalf("the comment was lost:\n%s", raw)
	}

	// A file linked to another cloud project keeps its link.
	p = write("version: 1\nproject: shop\ncloud: acme/other\nenvironments:\n  production:\n    STRIPE_KEY: team.stripe.key\n")
	if _, _, err := relinkTeam(p, target, names); err != nil {
		t.Fatal(err)
	}
	if config, _ := project.Load(p); config.Cloud != "acme/other" || config.Environments["production"]["STRIPE_KEY"] != "cloud.acme.shop.production.stripe-key" {
		t.Fatalf("envrune.yml is now %+v", config)
	}

	// Linking would turn a local cloud.* reference into a cloud one.
	before := "version: 1\nproject: shop\nenvironments:\n  production:\n    STRIPE_KEY: team.stripe.key\n    OLD: cloud.token\n"
	p = write(before)
	if _, _, err := relinkTeam(p, target, names); err == nil {
		t.Fatal("a local cloud.* reference was turned into a cloud one")
	}
	if raw, _ := os.ReadFile(p); string(raw) != before {
		t.Fatalf("a refused relink changed the file:\n%s", raw)
	}
}

func TestCloudImportTeamNeedsATeamFile(t *testing.T) {
	f := newFixture(t, cloudConfig)
	if code := f.run("cloud", "import-team"); code != 2 {
		t.Errorf("without a target = %d: %s", code, f.output())
	}
	if code := f.run("cloud", "import-team", "acme/shop/production"); code == 0 || !strings.Contains(f.output(), "envrune.team.json") {
		t.Errorf("without a team file = %d: %s", code, f.output())
	}
}

func TestCloudImportTeamShowsThePlanBeforeStoring(t *testing.T) {
	f := newFixture(t, baseConfig)
	if code := f.run("team", "init", "alice"); code != 0 {
		t.Fatalf("team init = %d: %s", code, f.output())
	}
	f.secrets = []string{"shared-team-value", "shared-team-value"}
	if code := f.run("set", "team.stripe.test"); code != 0 {
		t.Fatalf("set team ref = %d: %s", code, f.output())
	}
	f.choices = []string{"n"}
	code := f.run("cloud", "import-team", "acme/shop/production")
	out := f.output()
	if code == 0 || !strings.Contains(out, "team.stripe.test") || !strings.Contains(out, "-> acme/shop/production/stripe-test") || !strings.Contains(out, "Nothing was stored") {
		t.Fatalf("import-team = %d: %s", code, out)
	}
	if strings.Contains(out, "shared-team-value") {
		t.Fatalf("the plan showed a value: %s", out)
	}
}
