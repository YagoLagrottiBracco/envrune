package app

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

// fakeCloud serves fixed environments and records which ones were asked for.
type fakeCloud struct {
	envs  map[string]map[string]string // "org/project/env" → name → value
	roles map[string]string
	asked []string
}

func (f *fakeCloud) source(path cloud.Path) (map[string][]byte, string, error) {
	f.asked = append(f.asked, path.String())
	env, ok := f.envs[path.String()]
	if !ok {
		return nil, "", errors.New(path.String() + " is not on this device yet")
	}
	values := map[string][]byte{}
	for name, value := range env {
		values[name] = []byte(value)
	}
	return values, f.roles[path.String()], nil
}

func cloudProject(t *testing.T, link string, environments map[string]map[string]string) string {
	t.Helper()
	config := project.Config{Version: 1, Project: "shop", Cloud: link, Environments: map[string]map[string]domain.Reference{}}
	for environment, variables := range environments {
		config.Environments[environment] = map[string]domain.Reference{}
		for variable, raw := range variables {
			config.Environments[environment][variable] = domain.Reference(raw)
		}
	}
	path := filepath.Join(t.TempDir(), "envrune.yml")
	if err := project.WriteAtomic(path, config); err != nil {
		t.Fatal(err)
	}
	return path
}

func cloudSession(t *testing.T, f *fakeCloud) *Session {
	t.Helper()
	path, password := initializedVault(t)
	s, err := OpenSession(path, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Set("personal.local-only", []byte("local")); err != nil {
		t.Fatal(err)
	}
	s.UseCloudSource(f.source)
	return s
}

func TestCloudReferencesResolveNextToLocalOnes(t *testing.T) {
	f := &fakeCloud{envs: map[string]map[string]string{
		"acme/shop/production":   {"database-url": "postgres://prod", "stripe-key": "sk_live"},
		"acme/shared/production": {"sentry-dsn": "https://sentry"},
	}}
	s := cloudSession(t, f)
	projectPath := cloudProject(t, "acme/shop", map[string]map[string]string{"production": {
		"DATABASE_URL": "cloud.database-url",
		"STRIPE_KEY":   "cloud.stripe-key",
		"SENTRY_DSN":   "cloud.acme.shared.production.sentry-dsn",
		"LOCAL_ONLY":   "personal.local-only",
	}})
	resolved, err := s.Resolve(projectPath, "production")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range resolved.Pairs {
		got[p.Name] = string(p.Value)
	}
	want := map[string]string{"DATABASE_URL": "postgres://prod", "STRIPE_KEY": "sk_live", "SENTRY_DSN": "https://sentry", "LOCAL_ONLY": "local"}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("%s = %q, want %q", name, got[name], value)
		}
	}
	if resolved.Restricted {
		t.Fatal("a maintainer's values were marked restricted")
	}
	// Each environment is decrypted once per resolution.
	if len(f.asked) != 2 {
		t.Fatalf("asked the cloud %d times: %v", len(f.asked), f.asked)
	}
}

func TestConsumerValuesReachProcessesOnly(t *testing.T) {
	f := &fakeCloud{
		envs:  map[string]map[string]string{"acme/shop/production": {"stripe-key": "sk_live"}},
		roles: map[string]string{"acme/shop/production": cloudcrypto.RoleConsumer},
	}
	s := cloudSession(t, f)
	projectPath := cloudProject(t, "acme/shop", map[string]map[string]string{"production": {"STRIPE_KEY": "cloud.stripe-key"}})
	resolved, err := s.Resolve(projectPath, "production")
	if err != nil || !resolved.Restricted || len(resolved.Pairs) != 1 {
		t.Fatalf("a consumer's resolution was not restricted: %v", err)
	}
	if _, err := s.RevealIn(projectPath, "production", "cloud.stripe-key"); !errors.Is(err, ErrConsumerValue) {
		t.Fatalf("a consumer's value was revealed: %v", err)
	}
	if stored, err := s.HasIn(projectPath, "production", "cloud.stripe-key"); err != nil || !stored {
		t.Fatalf("a consumer's value did not count as stored: %v", err)
	}
	// Local values stay visible to the same user.
	if value, err := s.Reveal(projectPath, "personal.local-only"); err != nil || string(value) != "local" {
		t.Fatalf("a local value was refused: %v", err)
	}
}

func TestCloudReferencesNeedTheProjectLink(t *testing.T) {
	// An envrune.yml from before EnvRune Cloud may use local references that
	// start with "cloud."; without a cloud: key they stay local.
	f := &fakeCloud{}
	s := cloudSession(t, f)
	if err := s.Set("cloud.aws-key", []byte("local-aws")); err != nil {
		t.Fatal(err)
	}
	projectPath := cloudProject(t, "", map[string]map[string]string{"dev": {"AWS_KEY": "cloud.aws-key"}})
	resolved, err := s.Resolve(projectPath, "dev")
	if err != nil || string(resolved.Pairs[0].Value) != "local-aws" || len(f.asked) != 0 {
		t.Fatalf("a local cloud.* reference went to the cloud: %v %v", err, f.asked)
	}
}

func TestMissingCloudValuesAreNamed(t *testing.T) {
	f := &fakeCloud{envs: map[string]map[string]string{"acme/shop/production": {}}}
	s := cloudSession(t, f)
	projectPath := cloudProject(t, "acme/shop", map[string]map[string]string{
		"production": {"STRIPE_KEY": "cloud.stripe-key"},
		"staging":    {"STRIPE_KEY": "cloud.stripe-key"},
	})
	var missing *MissingSecretError
	if _, err := s.Resolve(projectPath, "production"); !errors.As(err, &missing) || missing.Missing[0].Variable != "STRIPE_KEY" {
		t.Fatalf("a missing cloud secret was not reported: %v", err)
	}
	var cloudErr *CloudError
	if _, err := s.Resolve(projectPath, "staging"); !errors.As(err, &cloudErr) {
		t.Fatalf("an environment missing from the cache was not a cloud error: %v", err)
	}
	if _, err := s.Reveal(projectPath, "cloud.stripe-key"); err == nil {
		t.Fatal("cloud.<name> resolved with no environment to pick")
	}
}

func TestSecretsIncludeCloudValuesForGuard(t *testing.T) {
	f := &fakeCloud{envs: map[string]map[string]string{"acme/shop/production": {"stripe-key": "sk_live"}}}
	s := cloudSession(t, f)
	projectPath := cloudProject(t, "acme/shop", map[string]map[string]string{"production": {"STRIPE_KEY": "cloud.stripe-key"}})
	secrets, err := s.Secrets(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret.Name == "cloud.stripe-key" && string(secret.Value) == "sk_live" {
			return
		}
	}
	t.Fatalf("guard would not see the cloud value: %d secrets", len(secrets))
}

func TestCloudReferencesWithoutASourceSayHowToSignIn(t *testing.T) {
	path, password := initializedVault(t)
	s, err := OpenSession(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	projectPath := cloudProject(t, "acme/shop", map[string]map[string]string{"dev": {"KEY": "cloud.key"}})
	if _, err := s.Resolve(projectPath, "dev"); !errors.Is(err, ErrNoCloud) {
		t.Fatalf("got %v", err)
	}
}
