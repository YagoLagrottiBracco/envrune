package project

import (
	"bytes"
	"os"
	"path/filepath"
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
