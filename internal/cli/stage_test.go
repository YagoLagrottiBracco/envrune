package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const stagedConfig = "version: 1\nproject: demo\ndefault_env: development\nenvironments:\n  development:\n    TLS_KEY: demo.tls-key\n    DATABASE_URL: demo.database-url\n" +
	"files:\n  - TLS_KEY\nrender:\n  APP_CONFIG: config/app.yml.tmpl\n"

func stagedFixture(t *testing.T, config string) *fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the commands these tests run are POSIX shell")
	}
	f := newFixture(t, config)
	dir := filepath.Dir(f.projectPath)
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(key, []byte("-----BEGIN KEY-----\nline one\nline two\n-----END KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := f.run("set", "demo.tls-key", "--file", key); code != 0 {
		t.Fatalf("set --file = %d: %s", code, f.output())
	}
	if err := f.session.Set("demo.database-url", []byte("postgres://user:pass@db/shop")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	template := "datasource:\n  url: {{DATABASE_URL}}\n  other: {{ not a variable }}\n  helm: {{ .Values.x }}\n"
	if err := os.WriteFile(filepath.Join(dir, "config", "app.yml.tmpl"), []byte(template), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSecretsAreDeliveredAsFilesThatDoNotOutliveTheCommand(t *testing.T) {
	f := stagedFixture(t, stagedConfig)
	script := `echo "key=$TLS_KEY"; echo "config=$APP_CONFIG"; echo "mode=$(stat -c %a "$TLS_KEY" 2>/dev/null || stat -f %Lp "$TLS_KEY")"; echo "--key"; cat "$TLS_KEY"; echo "--config"; cat "$APP_CONFIG"`
	if code := f.run("run", "--no-redact", "--", "sh", "-c", script); code != 0 {
		t.Fatalf("run = %d: %s", code, f.output())
	}
	out := f.output()
	for _, want := range []string{"mode=600", "-----BEGIN KEY-----\nline one\nline two\n-----END KEY-----", "url: postgres://user:pass@db/shop",
		"other: {{ not a variable }}", "helm: {{ .Values.x }}"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	var keyPath, configPath string
	for _, line := range strings.Split(out, "\n") {
		if path, ok := strings.CutPrefix(line, "key="); ok {
			keyPath = path
		}
		if path, ok := strings.CutPrefix(line, "config="); ok {
			configPath = path
		}
	}
	if keyPath == "" || !strings.HasSuffix(configPath, "app.yml") || filepath.Dir(keyPath) != filepath.Dir(configPath) {
		t.Fatalf("paths: key %q, config %q", keyPath, configPath)
	}
	if strings.HasPrefix(keyPath, filepath.Dir(f.projectPath)) {
		t.Fatalf("the file was written inside the project: %s", keyPath)
	}
	if _, err := os.Stat(filepath.Dir(keyPath)); err == nil {
		t.Fatalf("the files outlived the command: %s", filepath.Dir(keyPath))
	}
}

func TestATemplateThatNamesAnUndefinedVariableStopsTheCommand(t *testing.T) {
	f := stagedFixture(t, stagedConfig)
	template := filepath.Join(filepath.Dir(f.projectPath), "config", "app.yml.tmpl")
	if err := os.WriteFile(template, []byte("url: {{DATABASE_URL}}\npassword: {{MISSING_ONE}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code := f.run("run", "--", "sh", "-c", "echo started")
	if code == 0 || strings.Contains(f.output(), "started") || !strings.Contains(f.output(), "MISSING_ONE") {
		t.Fatalf("run = %d: %s", code, f.output())
	}
	if strings.Contains(f.output(), "postgres://") {
		t.Fatalf("the error shows a value: %s", f.output())
	}
}

func TestRenderFillsInATemplateForOneRun(t *testing.T) {
	f := stagedFixture(t, strings.Replace(stagedConfig, "render:\n  APP_CONFIG: config/app.yml.tmpl\n", "", 1))
	dir := filepath.Dir(f.projectPath)
	template := filepath.Join(dir, "nginx.conf.tmpl")
	if err := os.WriteFile(template, []byte("proxy_pass {{DATABASE_URL}};\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := f.run("render", template, "--no-redact", "--", "sh", "-c", `cat "$ENVRUNE_RENDERED"; echo "name=$(basename "$ENVRUNE_RENDERED")"`); code != 0 {
		t.Fatalf("render = %d: %s", code, f.output())
	}
	if out := f.output(); !strings.Contains(out, "proxy_pass postgres://user:pass@db/shop;") || !strings.Contains(out, "name=nginx.conf") {
		t.Fatalf("render output:\n%s", out)
	}
	if code := f.run("render", template, "--as", "NGINX_CONF", "--", "sh", "-c", `test -f "$NGINX_CONF"`); code != 0 {
		t.Fatalf("render --as = %d: %s", code, f.output())
	}
	if code := f.run("render", template); code != 2 {
		t.Fatalf("render without a command = %d", code)
	}
	if code := f.run("render", filepath.Join(dir, "missing.tmpl"), "--", "true"); code == 0 {
		t.Fatal("render of a missing template succeeded")
	}
}

func TestChecksReportWhichSecretsStillWork(t *testing.T) {
	config := stagedConfig + "checks:\n  database: sh -c 'test \"$DATABASE_URL\" = postgres://user:pass@db/shop'\n  payments: sh -c 'echo refused $DATABASE_URL; exit 3'\n"
	f := stagedFixture(t, config)
	code := f.run("check")
	out := f.output()
	if code != 1 || !strings.Contains(out, "database passed") || !strings.Contains(out, "payments failed (exit 3)") || !strings.Contains(out, "1 of 2 checks failed") {
		t.Fatalf("check = %d:\n%s", code, out)
	}
	// What a failing check printed is shown, with the value masked.
	if !strings.Contains(out, "refused ****") || strings.Contains(out, "postgres://") {
		t.Fatalf("a check's output was not masked:\n%s", out)
	}
	if code := f.run("check", "database"); code != 0 {
		t.Fatalf("check database = %d: %s", code, f.output())
	}
	if code := f.run("check", "nothing"); code != 2 {
		t.Fatalf("an unknown check = %d", code)
	}
}

func TestSetFileRefusesWhatIsNotASecretFile(t *testing.T) {
	f := newFixture(t, baseConfig)
	dir := t.TempDir()
	empty, big := filepath.Join(dir, "empty"), filepath.Join(dir, "big")
	_ = os.WriteFile(empty, nil, 0600)
	_ = os.WriteFile(big, make([]byte, maxSecretFile+1), 0600)
	for _, path := range []string{empty, big, filepath.Join(dir, "missing")} {
		if code := f.run("set", "demo.file", "--file", path); code == 0 {
			t.Errorf("set --file %s succeeded", filepath.Base(path))
		}
	}
}
