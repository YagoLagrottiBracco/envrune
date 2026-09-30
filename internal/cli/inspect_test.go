package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectDescribesTheProjectWithoutValues(t *testing.T) {
	f := newFixture(t, baseConfig+"commands:\n  dev: npm run dev\n")
	if err := f.session.Set("demo.key", []byte("sk-inspect-value")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "development", "API_KEY", "demo.key"); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "production", "API_KEY", "demo.missing"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENVRUNE_VAULT", f.vaultPath)
	t.Setenv("ENVRUNE_PASSWORD", "fixture-password")
	var stdout, stderr bytes.Buffer
	if code := executeInspect([]string{"--dir", filepath.Dir(f.projectPath)}, &stdout, &stderr); code != 0 {
		t.Fatalf("inspect = %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "sk-inspect-value") {
		t.Fatalf("inspect printed a value: %s", stdout.String())
	}
	var got inspectResult
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Project != "demo" || got.DefaultEnv != "development" || got.Locked || len(got.Commands) != 1 || len(got.Environments) != 2 {
		t.Fatalf("inspect = %+v", got)
	}
	stored := map[string]bool{}
	for _, environment := range got.Environments {
		for _, v := range environment.Variables {
			stored[environment.Environment+"/"+v.Reference] = v.Stored != nil && *v.Stored
		}
	}
	if !stored["development/demo.key"] || stored["production/demo.missing"] {
		t.Fatalf("stored = %v", stored)
	}

	t.Setenv("ENVRUNE_PASSWORD", "")
	stdout.Reset()
	if code := executeInspect([]string{"--dir", filepath.Dir(f.projectPath)}, &stdout, &stderr); code != 0 {
		t.Fatalf("inspect while locked = %d: %s", code, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil || !got.Locked {
		t.Fatalf("inspect while locked = %s, %v", stdout.String(), err)
	}
}
