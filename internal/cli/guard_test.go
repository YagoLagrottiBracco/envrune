package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/redact"
)

func TestFindInDiffReportsFileLineAndReference(t *testing.T) {
	pem := "-----BEGIN KEY-----\nMIIBOgIBAAJBAKj34GkxFhD9\n-----END KEY-----"
	matcher := redact.NewMatcher([]redact.Secret{
		{Name: "stripe.key", Value: []byte("sk_live_abcdef123")},
		{Name: "tls.key", Value: []byte(pem)},
	})
	diff := `diff --git a/app/config.py b/app/config.py
index 1111111..2222222 100644
--- a/app/config.py
+++ b/app/config.py
@@ -10,0 +11,2 @@ import os
+DEBUG = True
+STRIPE = "sk_live_abcdef123"
diff --git "a/docs/my notes.md" "b/docs/my notes.md"
new file mode 100644
--- /dev/null
+++ "b/docs/my notes.md"
@@ -0,0 +1,4 @@
+notes
+-----BEGIN KEY-----
+MIIBOgIBAAJBAKj34GkxFhD9
+-----END KEY-----
diff --git a/old.txt b/old.txt
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-sk_live_abcdef123
`
	got := findInDiff([]byte(diff), matcher)
	want := []leak{{"app/config.py", 12, "stripe.key"}, {"docs/my notes.md", 2, "tls.key"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("findInDiff() = %+v, want %+v", got, want)
	}
}

func TestHunkStartReadsNewLineNumber(t *testing.T) {
	for header, want := range map[string]int{"@@ -1 +1 @@": 1, "@@ -10,0 +11,2 @@ func": 11, "@@ -0,0 +1,40 @@": 1} {
		if got := hunkStart(header); got != want {
			t.Fatalf("hunkStart(%q) = %d, want %d", header, got, want)
		}
	}
}

// gitRepo creates a repository with a vault that ENVRUNE_VAULT and
// ENVRUNE_PASSWORD open, and returns the guard to run in it.
func gitRepo(t *testing.T, secrets map[string]string) (guard, *bytes.Buffer) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault", "vault.ev1")
	password := []byte("guard-password")
	if _, err := (app.VaultService{}).Init(vaultPath, password, password); err != nil {
		t.Fatal(err)
	}
	session, err := app.OpenSession(vaultPath, password)
	if err != nil {
		t.Fatal(err)
	}
	for ref, value := range secrets {
		if err := session.Set(ref, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	session.Close()
	repo := filepath.Join(dir, "repo")
	for _, args := range [][]string{{"init", "-q", repo}, {"-C", repo, "config", "user.email", "t@example.com"}, {"-C", repo, "config", "user.name", "T"}, {"-C", repo, "config", "commit.gpgsign", "false"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	env := map[string]string{"ENVRUNE_VAULT": vaultPath, "ENVRUNE_PASSWORD": string(password), "NO_COLOR": "1"}
	var out bytes.Buffer
	return guard{dir: repo, getenv: func(k string) string { return env[k] }, stdout: &out, stderr: &out}, &out
}

func stage(t *testing.T, repo, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "add", name).CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
}

func TestGuardBlocksStagedValuesWithoutPrintingThem(t *testing.T) {
	g, out := gitRepo(t, map[string]string{"stripe.key": "sk_live_guard_value"})
	stage(t, g.dir, "clean.txt", "nothing to see\n")
	if code := g.run(nil); code != 0 {
		t.Fatalf("guard on clean changes = %d: %s", code, out)
	}
	stage(t, g.dir, "config.js", "const a = 1\nconst key = 'sk_live_guard_value'\n")
	out.Reset()
	if code := g.run(nil); code != 1 {
		t.Fatalf("guard = %d, want 1: %s", code, out)
	}
	if !strings.Contains(out.String(), "config.js:2 contains the value of stripe.key") || strings.Contains(out.String(), "guard_value") {
		t.Fatalf("guard output = %s", out)
	}
}

func TestGuardWithALockedVaultWarnsOrBlocks(t *testing.T) {
	g, out := gitRepo(t, map[string]string{"stripe.key": "sk_live_guard_value"})
	stage(t, g.dir, "config.js", "sk_live_guard_value\n")
	env := map[string]string{"ENVRUNE_VAULT": g.getenv("ENVRUNE_VAULT"), "NO_COLOR": "1"}
	g.getenv = func(k string) string { return env[k] }
	if code := g.run(nil); code != 0 || !strings.Contains(out.String(), "not checked") {
		t.Fatalf("guard with a locked vault = %d: %s", code, out)
	}
	out.Reset()
	if code := g.run([]string{"--strict"}); code != 1 {
		t.Fatalf("guard --strict with a locked vault = %d: %s", code, out)
	}
}

func TestGuardInstallWritesAHookAndRefusesToReplaceAnother(t *testing.T) {
	g, out := gitRepo(t, nil)
	if code := g.run([]string{"install"}); code != 0 {
		t.Fatalf("install = %d: %s", code, out)
	}
	hook, _ := g.hookPath()
	script, err := os.ReadFile(hook)
	if err != nil || !strings.Contains(string(script), "guard") {
		t.Fatalf("hook = %q, %v", script, err)
	}
	if code := g.run([]string{"install"}); code != 0 {
		t.Fatalf("second install = %d: %s", code, out)
	}
	if code := g.run([]string{"uninstall"}); code != 0 {
		t.Fatalf("uninstall = %d: %s", code, out)
	}
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nnpm test\n"), 0755); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := g.run([]string{"install"}); code != 1 || !strings.Contains(out.String(), "already exists") {
		t.Fatalf("install over another hook = %d: %s", code, out)
	}
	if script, _ := os.ReadFile(hook); string(script) != "#!/bin/sh\nnpm test\n" {
		t.Fatal("install replaced a hook it did not write")
	}
}
