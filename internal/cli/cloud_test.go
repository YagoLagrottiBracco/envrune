package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

const cloudConfig = "version: 1\nproject: shop\ncloud: acme/shop\ndefault_env: production\nenvironments:\n  production:\n    STRIPE_KEY: cloud.stripe-key\n"

func cloudFixture(t *testing.T, role string) *fixture {
	t.Helper()
	f := newFixture(t, cloudConfig)
	f.session.UseCloudSource(func(path cloud.Path) (map[string][]byte, string, error) {
		if path.String() != "acme/shop/production" {
			return nil, "", os.ErrNotExist
		}
		return map[string][]byte{"stripe-key": []byte("sk_live_consumer_value")}, role, nil
	})
	return f
}

func TestConsumersCannotShowCloudValues(t *testing.T) {
	f := cloudFixture(t, cloudcrypto.RoleConsumer)
	output := filepath.Join(t.TempDir(), ".env")
	for _, args := range [][]string{
		{"run", "--no-redact", "--", "anything"},
		{"export", "--output", output},
		{"env", "--format", "json"},
		{"copy", "cloud.stripe-key"},
	} {
		if code := f.run(args...); code == 0 {
			t.Errorf("%s succeeded for a consumer", args[0])
		}
		if strings.Contains(f.output(), "sk_live_consumer_value") {
			t.Fatalf("%s showed the value: %s", args[0], f.output())
		}
		if !strings.Contains(f.output(), "consumer") {
			t.Errorf("%s did not say why: %s", args[0], f.output())
		}
	}
	if _, err := os.Stat(output); err == nil {
		t.Fatal("export wrote a consumer's values")
	}
}

func TestMaintainersExportCloudValues(t *testing.T) {
	f := cloudFixture(t, cloudcrypto.RoleMaintainer)
	f.secrets = []string{"YES"}
	output := filepath.Join(t.TempDir(), ".env")
	if code := f.run("export", "--output", output); code != 0 {
		t.Fatalf("export = %d: %s", code, f.output())
	}
	raw, _ := os.ReadFile(output)
	if !strings.Contains(string(raw), "STRIPE_KEY=sk_live_consumer_value") {
		t.Fatalf("export wrote %q", raw)
	}
}

func TestLinkingAMissingCloudSecretPointsToTheCloud(t *testing.T) {
	f := cloudFixture(t, cloudcrypto.RoleMaintainer)
	// No prompt: a cloud secret is never stored in the local vault.
	if code := f.run("link", "DATABASE_URL", "cloud.database-url"); code != 0 {
		t.Fatalf("link = %d: %s", code, f.output())
	}
	if !strings.Contains(f.output(), "envrune cloud set acme/shop/production/database-url") {
		t.Fatalf("output = %s", f.output())
	}
}

func TestMachineTokenOpensASessionWithoutAVault(t *testing.T) {
	dir := t.TempDir()
	projectPath := filepath.Join(dir, "envrune.yml")
	if err := os.WriteFile(projectPath, []byte(cloudConfig), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ENVRUNE_VAULT": filepath.Join(dir, "missing.ev1"), "ENVRUNE_TOKEN": "envrune_mt_x.y.z.w"}
	u := unlocker{getenv: func(k string) string { return env[k] }, noPrompt: true}
	session, err := u.session()
	if err != nil {
		t.Fatalf("no session from ENVRUNE_TOKEN: %v", err)
	}
	defer session.Close()
	if cloud.DefaultServer == "" {
		if _, err := session.Resolve(projectPath, ""); err == nil || !strings.Contains(err.Error(), "ENVRUNE_CLOUD_SERVER") {
			t.Fatalf("resolving did not ask for the server: %v", err)
		}
	}
	env["ENVRUNE_CLOUD_SERVER"] = "http://example.com"
	if _, err := session.Resolve(projectPath, ""); err == nil || !strings.Contains(err.Error(), "machine token") {
		t.Fatalf("the token was not used: %v", err)
	}
}
