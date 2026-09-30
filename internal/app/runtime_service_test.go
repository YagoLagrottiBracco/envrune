package app

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/dotenv"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

func TestGenerateStoresGeneratedSecret(t *testing.T) {
	path, password := initializedVault(t)
	service := VaultService{}
	if err := service.Generate(path, "openai.generated", 48, password); err != nil {
		t.Fatal(err)
	}
	values, err := service.ResolveEnvironment(path, writeProject(t, map[string]map[string]string{
		"dev": {"OPENAI_API_KEY": "openai.generated"},
	}), "dev", password)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Name != "OPENAI_API_KEY" || len(values[0].Value) != 48 {
		t.Fatalf("generated value was not stored: %#v", values)
	}
}

func TestImportRejectsInvalidEntriesWithoutMutatingVault(t *testing.T) {
	path, password := initializedVault(t)
	const sentinel = "envrune-test-secret-DO-NOT-LEAK"
	_, err := (VaultService{}).Import(path, []dotenv.Entry{{Name: "BAD-NAME", Value: []byte(sentinel)}}, password)
	if err == nil {
		t.Fatal("Import unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatal("secret sentinel leaked through import error")
	}
	refs, err := (VaultService{}).List(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("invalid import mutated vault: %v", refs)
	}
}

func TestImportStoresValuesUnderDeterministicReferences(t *testing.T) {
	path, password := initializedVault(t)
	count, err := (VaultService{}).Import(path, []dotenv.Entry{{Name: "OPENAI_API_KEY", Value: []byte("imported-value")}}, password)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("Import count = %d, want 1", count)
	}
	got, err := (VaultService{}).ResolveEnvironment(path, writeProject(t, map[string]map[string]string{
		"dev": {"OPENAI_API_KEY": "import.var-openai-api-key"},
	}), "dev", password)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []runner.Pair{{Name: "OPENAI_API_KEY", Value: []byte("imported-value")}}) {
		t.Fatalf("imported value was not stored: %#v", got)
	}
}

func TestResolveEnvironmentReturnsOnlySelectedMappings(t *testing.T) {
	path, password := initializedVault(t)
	service := VaultService{}
	if err := service.Set(path, password, "openai.dev", []byte("dev-value")); err != nil {
		t.Fatal(err)
	}
	if err := service.Set(path, password, "openai.prod", []byte("prod-value")); err != nil {
		t.Fatal(err)
	}
	projectPath := writeProject(t, map[string]map[string]string{
		"dev":  {"OPENAI_API_KEY": "openai.dev"},
		"prod": {"OPENAI_API_KEY": "openai.prod"},
	})
	got, err := service.ResolveEnvironment(path, projectPath, "dev", password)
	if err != nil {
		t.Fatal(err)
	}
	want := []runner.Pair{{Name: "OPENAI_API_KEY", Value: []byte("dev-value")}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveEnvironment() = %#v, want %#v", got, want)
	}
}

func TestResolveEnvironmentMissingReferenceReturnsValueFreeError(t *testing.T) {
	path, password := initializedVault(t)
	const sentinel = "envrune-test-secret-DO-NOT-LEAK"
	if err := (VaultService{}).Set(path, password, "other.secret", []byte(sentinel)); err != nil {
		t.Fatal(err)
	}
	_, err := (VaultService{}).ResolveEnvironment(path, writeProject(t, map[string]map[string]string{
		"dev": {"OPENAI_API_KEY": "missing.secret"},
	}), "dev", password)
	if err == nil {
		t.Fatal("ResolveEnvironment unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatal("secret sentinel leaked through resolution error")
	}
}

func initializedVault(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("correct horse battery staple")
	if err := (VaultService{}).Init(path, password, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	return path, password
}

func writeProject(t *testing.T, environments map[string]map[string]string) string {
	t.Helper()
	config := project.Config{Version: 1, Project: "runtime", Environments: make(map[string]map[string]domain.Reference, len(environments))}
	for environment, variables := range environments {
		config.Environments[environment] = make(map[string]domain.Reference, len(variables))
		for variable, rawReference := range variables {
			reference, err := domain.ParseReference(rawReference)
			if err != nil {
				t.Fatal(err)
			}
			config.Environments[environment][variable] = reference
		}
	}
	path := filepath.Join(t.TempDir(), "envrune.yml")
	if err := project.WriteAtomic(path, config); err != nil {
		t.Fatal(err)
	}
	return path
}
