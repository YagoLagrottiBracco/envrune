package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

type fixture struct {
	t           *testing.T
	vaultPath   string
	projectPath string
	session     *app.Session
	stdout      bytes.Buffer
	stderr      bytes.Buffer
	secrets     []string
	choices     []string
}

func newFixture(t *testing.T, config string) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, vaultPath: filepath.Join(dir, "vault", "vault.ev1"), projectPath: filepath.Join(dir, "project", "envrune.yml")}
	password := []byte("fixture-password")
	if _, err := (app.VaultService{}).Init(f.vaultPath, password, password); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(f.projectPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.projectPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	session, err := app.OpenSession(f.vaultPath, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	f.session = session
	return f
}

func (f *fixture) workspace() Workspace {
	return Workspace{
		Session: f.session,
		Stdout:  &f.stdout,
		Stderr:  &f.stderr,
		ReadSecret: func(label string) ([]byte, error) {
			if len(f.secrets) == 0 {
				f.t.Fatalf("unexpected prompt %q", label)
			}
			value := f.secrets[0]
			f.secrets = f.secrets[1:]
			return []byte(value), nil
		},
		ReadChoice: func(string) (string, error) {
			value := f.choices[0]
			f.choices = f.choices[1:]
			return value, nil
		},
		FindProject: func(string) (string, error) { return f.projectPath, nil },
		Environment: os.Environ,
	}
}

func (f *fixture) run(args ...string) int {
	f.t.Helper()
	f.stdout.Reset()
	f.stderr.Reset()
	return f.workspace().Execute(args)
}

func (f *fixture) output() string { return f.stdout.String() + f.stderr.String() }

const baseConfig = "version: 1\nproject: demo\ndefault_env: development\nenvironments:\n  development: {}\n  production: {}\n"

func TestLinkOffersToCreateMissingSecretAndUsesDefaultEnv(t *testing.T) {
	f := newFixture(t, baseConfig)
	f.choices = []string{"y"}
	f.secrets = []string{"sk-demo", "sk-demo"}
	if code := f.run("link", "API_KEY", "demo.api-key"); code != 0 {
		t.Fatalf("link = %d: %s", code, f.output())
	}
	if !strings.Contains(f.output(), "for environment development") || !strings.Contains(f.output(), "Secret stored: demo.api-key") {
		t.Fatalf("output = %q", f.output())
	}
	resolved, err := f.session.Resolve(f.projectPath, "")
	if err != nil || resolved.Environment != "development" || string(resolved.Pairs[0].Value) != "sk-demo" {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
}

func TestRunNamedCommandAndUpWithDefaultEnvironment(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows host command fixture")
	}
	config := baseConfig + "commands:\n  hello: cmd /c echo hello %API_KEY%\n  other:\n    run: cmd /c echo other %API_KEY%\n    env: production\n"
	f := newFixture(t, config)
	if err := f.session.Set("demo.dev", []byte("dev-value")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Set("demo.prod", []byte("prod-value")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "development", "API_KEY", "demo.dev"); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "production", "API_KEY", "demo.prod"); err != nil {
		t.Fatal(err)
	}
	if code := f.run("hello"); code != 0 || !strings.Contains(f.stdout.String(), "hello dev-value") {
		t.Fatalf("hello = %d: %s", code, f.output())
	}
	if code := f.run("run", "cmd", "/c", "echo run %API_KEY%"); code != 0 || !strings.Contains(f.stdout.String(), "run dev-value") {
		t.Fatalf("run = %d: %s", code, f.output())
	}
	f.run("up", "hello", "other")
	for _, want := range []string{"hello | hello dev-value", "other | other prod-value"} {
		if !strings.Contains(f.stdout.String(), want) {
			t.Fatalf("up output misses %q: %s", want, f.output())
		}
	}
}

func TestTeamSecretsResolveForMembersAndInCI(t *testing.T) {
	f := newFixture(t, baseConfig)
	if code := f.run("team", "init", "alice"); code != 0 {
		t.Fatalf("team init = %d: %s", code, f.output())
	}
	f.secrets = []string{"shared-value", "shared-value"}
	if code := f.run("set", "team.stripe.test"); code != 0 {
		t.Fatalf("set team ref = %d: %s", code, f.output())
	}
	ci, err := team.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ciPublic, _ := team.PublicKey(ci)
	if code := f.run("team", "add", "ci", ciPublic); code != 0 {
		t.Fatalf("team add = %d: %s", code, f.output())
	}
	if err := f.session.Link(f.projectPath, "production", "STRIPE_KEY", "team.stripe.test"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(team.Path(f.projectPath))
	if strings.Contains(string(raw), "shared-value") {
		t.Fatal("team file leaked a value")
	}
	ciSession := app.NewIdentitySession(ci)
	defer ciSession.Close()
	resolved, err := ciSession.Resolve(f.projectPath, "production")
	if err != nil || string(resolved.Pairs[0].Value) != "shared-value" {
		t.Fatalf("CI Resolve() = %#v, %v", resolved, err)
	}
}

func TestDoctorFindsMissingReferencesDotenvFilesAndPastedValues(t *testing.T) {
	config := "version: 1\nproject: demo\ncommands:\n  dev: npm start --token=sk-abcdefghijklmnopqrstuvwx\nenvironments:\n  development:\n    API_KEY: demo.missing\n"
	f := newFixture(t, config)
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.projectPath), ".env"), []byte("A=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := f.run("doctor"); code != 1 {
		t.Fatalf("doctor = %d, want 1: %s", code, f.output())
	}
	for _, want := range []string{"demo.missing (used by API_KEY)", ".env holds plaintext values", "envrune.yml line 4 looks like it contains a secret"} {
		if !strings.Contains(f.output(), want) {
			t.Fatalf("doctor output misses %q:\n%s", want, f.output())
		}
	}
	if strings.Contains(f.output(), "sk-abcdefghijklmnopqrstuvwx") {
		t.Fatal("doctor echoed the pasted value")
	}
}

func TestEnvPrintsQuotedAssignmentsAndHookVariables(t *testing.T) {
	f := newFixture(t, baseConfig)
	if err := f.session.Set("demo.quote", []byte("it's $HOME")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "development", "QUOTED", "demo.quote"); err != nil {
		t.Fatal(err)
	}
	if code := f.run("env", "--hook"); code != 0 {
		t.Fatalf("env = %d: %s", code, f.output())
	}
	if want := "export QUOTED='it'\\''s $HOME'\nexport ENVRUNE_HOOK_VARS='QUOTED'\n"; f.stdout.String() != want {
		t.Fatalf("env output = %q", f.stdout.String())
	}
	if code := f.run("env", "--format", "powershell"); code != 0 || f.stdout.String() != "$env:QUOTED = 'it''s $HOME'\n" {
		t.Fatalf("powershell env = %d %q", code, f.stdout.String())
	}
}

func TestRotateKeepsHistoryAndRollbackRestores(t *testing.T) {
	f := newFixture(t, baseConfig)
	if err := f.session.Set("demo.token", []byte("original-value-1234")); err != nil {
		t.Fatal(err)
	}
	if code := f.run("rotate", "demo.token"); code != 0 {
		t.Fatalf("rotate = %d: %s", code, f.output())
	}
	value, _ := f.session.Reveal("", "demo.token")
	if string(value) == "original-value-1234" || len(value) != len("original-value-1234") {
		t.Fatalf("rotated value = %q", value)
	}
	if code := f.run("rollback", "demo.token"); code != 0 {
		t.Fatalf("rollback = %d: %s", code, f.output())
	}
	value, _ = f.session.Reveal("", "demo.token")
	if string(value) != "original-value-1234" {
		t.Fatalf("rolled back value = %q", value)
	}
	if code := f.run("meta", "demo.token", "--owner", "payments", "--expires", "2000-01-01"); code != 0 {
		t.Fatalf("meta = %d: %s", code, f.output())
	}
	f.run("doctor")
	if !strings.Contains(f.output(), "demo.token expired on 2000-01-01") {
		t.Fatalf("doctor did not report expiry: %s", f.output())
	}
}

func TestRecoverResetsPasswordAndRestoreReplacesVault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.ev1")
	t.Setenv("ENVRUNE_VAULT", path)
	recovery, err := (app.VaultService{}).Init(path, []byte("old"), []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	status := NewPresenter(&out, &errOut, os.Getenv)
	backup := filepath.Join(dir, "backup.ev1")
	if code := executeBackup([]string{backup}, status); code != 0 {
		t.Fatalf("backup = %d: %s", code, errOut.String())
	}
	answers := []string{vault.FormatRecoveryKey(recovery), "new", "new"}
	read := func(string) ([]byte, error) {
		value := answers[0]
		answers = answers[1:]
		return []byte(value), nil
	}
	if code := executeRecover(read, status); code != 0 {
		t.Fatalf("recover = %d: %s", code, errOut.String())
	}
	if _, err := app.OpenSession(path, []byte("new")); err != nil {
		t.Fatalf("new password does not open the vault: %v", err)
	}
	answers = []string{"old", "YES"}
	if code := executeRestore([]string{backup}, read, status); code != 0 {
		t.Fatalf("restore = %d: %s", code, errOut.String())
	}
	if _, err := app.OpenSession(path, []byte("old")); err != nil {
		t.Fatalf("restored vault does not open with the old password: %v", err)
	}
}

func TestHookScriptsAreAvailable(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var out bytes.Buffer
		if code := executeHook([]string{shell}, &out, &bytes.Buffer{}); code != 0 || !strings.Contains(out.String(), "envrune env --hook") {
			t.Fatalf("hook %s = %d: %s", shell, code, out.String())
		}
	}
}
