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
	config := baseConfig + "commands:\n  hello: " + echoCommand("hello") + "\n  other:\n    run: " + echoCommand("other") + "\n    env: production\n"
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
	if code := f.run("hello", "--no-redact"); code != 0 || !strings.Contains(f.stdout.String(), "hello dev-value") {
		t.Fatalf("hello = %d: %s", code, f.output())
	}
	if code := f.run("run", "--no-redact", "cmd", "/c", "echo run %API_KEY%"); code != 0 || !strings.Contains(f.stdout.String(), "run dev-value") {
		t.Fatalf("run = %d: %s", code, f.output())
	}
	f.run("up", "--no-redact", "hello", "other")
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

// echoCommand returns a commands: entry that prints label and $API_KEY, then
// stays up for two seconds, because `up` stops every service as soon as one
// exits.
func echoCommand(label string) string {
	if runtime.GOOS == "windows" {
		return `cmd /c "echo ` + label + ` %API_KEY% & ping -n 3 127.0.0.1 >nul"`
	}
	return `sh -c "echo ` + label + ` $API_KEY; sleep 2"`
}

func TestUpStartsServicesThatKeepTheirOwnEnvrune(t *testing.T) {
	config := baseConfig + "commands:\n" +
		"  api:\n    run: " + echoCommand("api") + "\n    project: api\n" +
		"  web:\n    run: " + echoCommand("web") + "\n    project: web\n    env: staging\n" +
		"  ghost:\n    run: " + echoCommand("ghost") + "\n    project: nope\n" +
		"up: [api, web]\n"
	f := newFixture(t, config)
	root := filepath.Dir(f.projectPath)
	write := func(rel, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("api/envrune.yml", "version: 1\nproject: api\ndefault_env: development\nenvironments:\n  development:\n    API_KEY: api.key\n")
	write("web/envrune.yml", "version: 1\nproject: web\ndefault_env: development\nenvironments:\n  development: {}\n  staging:\n    API_KEY: web.staging\n")
	for ref, value := range map[string]string{"api.key": "api-value", "web.staging": "web-staging"} {
		if err := f.session.Set(ref, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if code := f.run("up", "--no-redact"); code != 0 {
		t.Fatalf("up = %d: %s", code, f.output())
	}
	for _, want := range []string{"api | api api-value", "web | web web-staging", "from development in api", "from staging in web"} {
		if !strings.Contains(f.output(), want) {
			t.Fatalf("up output misses %q: %s", want, f.output())
		}
	}
	if code := f.run("ghost"); code == 0 || !strings.Contains(f.output(), "nope/envrune.yml was not found") {
		t.Fatalf("ghost = %d: %s", code, f.output())
	}
	f.run("doctor")
	for _, want := range []string{"project api (used by commands.api)", "commands.ghost uses project nope, but it has no envrune.yml"} {
		if !strings.Contains(f.output(), want) {
			t.Fatalf("doctor output misses %q: %s", want, f.output())
		}
	}
}

func TestRunAndUpMaskValuesUnlessAskedNotTo(t *testing.T) {
	config := baseConfig + "commands:\n" +
		"  one: " + echoCommand("one") + "\n" +
		"  two:\n    run: " + echoCommand("two") + "\n    env: production\n"
	f := newFixture(t, config)
	for ref, value := range map[string]string{"demo.dev": "dev-secret-value", "demo.prod": "prod-secret-value"} {
		if err := f.session.Set(ref, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.session.Link(f.projectPath, "development", "API_KEY", "demo.dev"); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "production", "API_KEY", "demo.prod"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"one"}, {"up", "one", "two"}} {
		f.run(args...)
		if strings.Contains(f.output(), "secret-value") {
			t.Fatalf("%v printed a value:\n%s", args, f.output())
		}
		if !strings.Contains(f.output(), "one ****") {
			t.Fatalf("%v output = %s", args, f.output())
		}
	}
	if !strings.Contains(f.output(), "two ****") {
		t.Fatalf("up output = %s", f.output())
	}
	f.run("one", "--no-redact")
	if !strings.Contains(f.output(), "one dev-secret-value") {
		t.Fatalf("--no-redact output = %s", f.output())
	}
}

func TestDoctorListsValuesTooShortToMask(t *testing.T) {
	f := newFixture(t, baseConfig)
	for ref, value := range map[string]string{"demo.port": "3000", "demo.key": "long-enough-value"} {
		if err := f.session.Set(ref, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	for variable, ref := range map[string]string{"PORT": "demo.port", "API_KEY": "demo.key"} {
		if err := f.session.Link(f.projectPath, "development", variable, ref); err != nil {
			t.Fatal(err)
		}
	}
	f.run("doctor")
	if !strings.Contains(f.output(), "environment development: PORT is shorter than 6 characters") || strings.Contains(f.output(), "API_KEY is shorter") {
		t.Fatalf("doctor output = %s", f.output())
	}
}

const variablesConfig = `version: 1
project: shop
default_env: development
variables:
  DATABASE_URL:
    description: Postgres for the app
    how_to_get: Run make db
    type: url
  STRIPE_KEY:
    format: ^sk_test_
  LOG_LEVEL:
    required: false
environments:
  development: {}
`

func TestRunChecksDocumentedVariables(t *testing.T) {
	f := newFixture(t, variablesConfig)
	if err := f.session.Set("shop.db", []byte("not-a-url-secret")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "development", "DATABASE_URL", "shop.db"); err != nil {
		t.Fatal(err)
	}
	if code := f.run("run", "--", "anything"); code == 0 {
		t.Fatalf("run started with invalid variables: %s", f.output())
	}
	out := f.output()
	for _, want := range []string{"DATABASE_URL (shop.db) is not a URL", "STRIPE_KEY is required but not linked in development", "envrune setup"} {
		if !strings.Contains(out, want) {
			t.Fatalf("run output misses %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not-a-url-secret") || strings.Contains(out, "LOG_LEVEL") {
		t.Fatalf("run output = %s", out)
	}
}

func TestSetupGuidesThroughEachVariable(t *testing.T) {
	f := newFixture(t, variablesConfig)
	// DATABASE_URL: accept the suggested reference, give an invalid value,
	// then a valid one. STRIPE_KEY: choose a reference. LOG_LEVEL: skip.
	f.choices = []string{"", "shop.stripe.test", "n"}
	f.secrets = []string{"nope", "nope", "postgres://db/app", "postgres://db/app", "sk_test_123", "sk_test_123"}
	if code := f.run("setup"); code != 0 {
		t.Fatalf("setup = %d:\n%s", code, f.output())
	}
	out := f.output()
	for _, want := range []string{"Postgres for the app", "How to get it: Run make db", "Expected: a URL", "That value is not a URL", "DATABASE_URL is ready (shop.database-url.development)", "STRIPE_KEY is ready (shop.stripe.test)", "2 of 3 variables are ready"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup output misses %q:\n%s", want, out)
		}
	}
	resolved, err := f.session.Resolve(f.projectPath, "")
	if err != nil || len(resolved.Pairs) != 2 {
		t.Fatalf("Resolve() after setup = %+v, %v", resolved, err)
	}
	f.choices, f.secrets = []string{"n"}, nil
	if code := f.run("setup"); code != 0 || !strings.Contains(f.output(), "DATABASE_URL is ready") {
		t.Fatalf("second setup = %d:\n%s", code, f.output())
	}
}

func TestDiffComparesEnvironmentsByName(t *testing.T) {
	config := `version: 1
project: shop
environments:
  development:
    DATABASE_URL: shop.db.dev
    STRIPE_KEY: shop.stripe.test
    DEBUG_TOOLBAR: shop.debug
  production:
    DATABASE_URL: shop.db.prod
    STRIPE_KEY: shop.stripe.test
    SENTRY_DSN: shop.sentry
`
	f := newFixture(t, config)
	if code := f.run("diff", "development", "production"); code != 1 {
		t.Fatalf("diff = %d:\n%s", code, f.output())
	}
	out := f.output()
	for _, want := range []string{"Only in development (1):\n  DEBUG_TOOLBAR", "Only in production (1):\n  SENTRY_DSN", "STRIPE_KEY → shop.stripe.test", "share 1 reference"} {
		if !strings.Contains(out, want) {
			t.Fatalf("diff output misses %q:\n%s", want, out)
		}
	}
	if code := f.run("diff", "development", "staging"); code == 0 || !strings.Contains(f.output(), `"staging" does not exist; available: development, production`) {
		t.Fatalf("diff with unknown env = %d:\n%s", code, f.output())
	}
}
