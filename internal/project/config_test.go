package project

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
)

func TestLoadAcceptsVersionedProjectMappings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	data := "version: 1\nproject: pulsewatch\nenvironments:\n  dev:\n    OPENAI_API_KEY: openai.personal\n  prod:\n    OPENAI_API_KEY: openai.production\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Project != "pulsewatch" || got.Environments["dev"]["OPENAI_API_KEY"].String() != "openai.personal" {
		t.Fatalf("unexpected config: %#v", got)
	}
}

func TestLoadRejectsUnsafeMappings(t *testing.T) {
	for _, data := range []string{
		"version: 1\nproject: x\nenvironments:\n  dev:\n    bad-name: openai.personal\n",
		"version: 1\nproject: x\nenvironments:\n  dev:\n    OPENAI_API_KEY: OpenAI.personal\n",
		"version: 1\nproject: x\nenvironments:\n  dev:\n    OPENAI_API_KEY: openai.personal\n    OPENAI_API_KEY: other\n",
	} {
		p := filepath.Join(t.TempDir(), "envrune.yml")
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatal("Load() accepted unsafe config")
		}
	}
}

func TestWriteAtomicPreservesMappings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	refA, _ := domain.ParseReference("openai.personal")
	refB, _ := domain.ParseReference("resend.personal")
	want := Config{Version: 1, Project: "pulsewatch", Environments: map[string]map[string]domain.Reference{
		"dev": {"OPENAI_API_KEY": refA, "RESEND_API_KEY": refB},
	}}
	if err := WriteAtomic(p, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Environments["dev"]["OPENAI_API_KEY"] != refA || got.Environments["dev"]["RESEND_API_KEY"] != refB {
		t.Fatalf("mappings not preserved: %#v", got)
	}
}

func TestProjectConfigurationNeverContainsSecretSentinel(t *testing.T) {
	const sentinel = "envrune-test-secret-DO-NOT-LEAK"
	p := filepath.Join(t.TempDir(), "envrune.yml")
	ref, _ := domain.ParseReference("openai.personal")
	if err := WriteAtomic(p, Config{Version: 1, Project: "x", Environments: map[string]map[string]domain.Reference{"dev": {"OPENAI_API_KEY": ref}}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(sentinel)) {
		t.Fatal("secret sentinel leaked")
	}
}

func TestWriteAtomicRejectsEmptyEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	ref, _ := domain.ParseReference("openai.personal")
	if err := WriteAtomic(p, Config{Version: 1, Project: "x", Environments: map[string]map[string]domain.Reference{"": {"OPENAI_API_KEY": ref}}}); err == nil {
		t.Fatal("WriteAtomic accepted an empty environment")
	}
}

func TestLoadReadsDefaultEnvCommandsAndUp(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	data := `version: 1
project: shop
default_env: development
commands:
  web: npm run dev
  api:
    run: .venv/bin/python -m uvicorn main:app --port 8000
    dir: api
up: [api, web]
environments:
  development: {}
`
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.DefaultEnv != "development" || got.Commands["web"].Run != "npm run dev" || got.Commands["api"].Dir != "api" || len(got.Up) != 2 {
		t.Fatalf("unexpected config: %#v", got)
	}
	if problems := got.Validate(); len(problems) != 0 {
		t.Fatalf("Validate() = %v", problems)
	}
}

func TestLoadExplainsWhereConfigIsWrongWithoutEchoingValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	data := "version: 1\nproject: x\nenvironments:\n  dev:\n    API_KEY: sk-live-DO-NOT-LEAK\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	var configErr *ConfigError
	if !errors.As(err, &configErr) || configErr.Line != 5 || strings.Contains(err.Error(), "DO-NOT-LEAK") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestSetBindingKeepsCommentsAndOtherSections(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	data := "# team project\nversion: 1\nproject: x\ndefault_env: dev\ncommands:\n  dev: npm start # local\nenvironments: {}\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SetBinding(p, "dev", "API_KEY", "demo.key"); err != nil {
		t.Fatal(err)
	}
	if err := SetBinding(p, "dev", "API_KEY", "demo.other"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	for _, want := range []string{"# team project", "# local", "default_env: dev", "API_KEY: demo.other"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %q in:\n%s", want, raw)
		}
	}
	got, err := Load(p)
	if err != nil || got.Environments["dev"]["API_KEY"] != "demo.other" || got.Commands["dev"].Run != "npm start" {
		t.Fatalf("Load() = %#v, %v", got, err)
	}
}

func TestExampleConfigurationIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "envrune.yml")
	if _, err := os.Stat(path); err != nil {
		t.Skip("run from the source tree to check the example")
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if problems := config.Validate(); len(problems) != 0 {
		t.Fatalf("examples/envrune.yml: %v", problems)
	}
}

func TestCommandProjectPointsToAnotherEnvrune(t *testing.T) {
	p := filepath.Join(t.TempDir(), "envrune.yml")
	data := "version: 1\nproject: shop\ncommands:\n  api:\n    run: npm start\n    project: services/api\n    env: staging\n  web:\n    run: npm run dev\n    project: web\n    dir: web/app\nenvironments: {}\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if problems := config.Validate(); len(problems) != 0 {
		t.Fatalf("Validate() = %v; env belongs to the other file", problems)
	}
	root := filepath.Dir(p)
	secrets, dir := config.Commands["api"].Target(p)
	if secrets != filepath.Join(root, "services", "api", "envrune.yml") || dir != filepath.Join(root, "services", "api") {
		t.Fatalf("api Target() = %s, %s", secrets, dir)
	}
	if _, dir := config.Commands["web"].Target(p); dir != filepath.Join(root, "web", "app") {
		t.Fatalf("web dir = %s", dir)
	}
	if err := WriteAtomic(p, config); err != nil {
		t.Fatal(err)
	}
	if again, err := Load(p); err != nil || again.Commands["api"].Project != "services/api" {
		t.Fatalf("round trip = %#v, %v", again.Commands, err)
	}
	for _, bad := range []string{"/srv/api", `C:\api`, `\api`, `""`} {
		data := "version: 1\nproject: x\ncommands:\n  api:\n    run: npm start\n    project: " + bad + "\nenvironments: {}\n"
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("Load() accepted project %s", bad)
		}
	}
}

func TestLoadReadsTheCloudLink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "envrune.yml")
	data := "version: 1\nproject: shop\ncloud: acme/shop\nenvironments:\n  production:\n    DATABASE_URL: cloud.database-url\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got.Cloud != "acme/shop" {
		t.Fatalf("Load() = %#v, %v", got, err)
	}
	// Written back, the link stays.
	if err := WriteAtomic(p, got); err != nil {
		t.Fatal(err)
	}
	if again, err := Load(p); err != nil || again.Cloud != "acme/shop" {
		t.Fatalf("the link was lost: %#v, %v", again, err)
	}
	for _, bad := range []string{"acme", "acme/shop/production", "Acme/shop", "acme/"} {
		data := "version: 1\nproject: shop\ncloud: " + bad + "\nenvironments: {}\n"
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("cloud: %s was accepted", bad)
		}
	}
}
