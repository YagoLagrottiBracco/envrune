//go:build integration

// Package integration runs the envrune binary the way a user does, with a
// real vault, real child processes, and several envrune processes at once.
// Run it with:
//
//	go test -tags integration ./test/integration
package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/filelock"
)

const password = "integration-password"

var envruneBin, binDir string

// TestMain builds envrune and probe, or, when ENVRUNE_IT_BIN names a folder
// that already holds both, uses those. That runs the suite where Go is not
// installed, such as a cross-compiled test binary in a VM.
func TestMain(m *testing.M) {
	if dir := os.Getenv("ENVRUNE_IT_BIN"); dir != "" {
		binDir, envruneBin = dir, filepath.Join(dir, "envrune"+exeSuffix())
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "envrune-it-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binDir = dir
	envruneBin = filepath.Join(dir, "envrune"+exeSuffix())
	for out, pkg := range map[string]string{envruneBin: "./cmd/envrune", filepath.Join(dir, "probe"+exeSuffix()): "./test/integration/testdata/probe"} {
		build := exec.Command("go", "build", "-o", out, pkg)
		build.Dir = filepath.Join("..", "..")
		build.Stdout, build.Stderr = os.Stderr, os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "building %s: %v\n", pkg, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// harness is one user's machine: a vault, projects, and the envrune binary.
type harness struct {
	t     *testing.T
	root  string
	vault string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{t: t, root: root, vault: filepath.Join(root, "data", "vault.ev1")}
	if _, err := (app.VaultService{}).Init(h.vault, []byte(password), []byte(password)); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) set(ref, value string) {
	h.t.Helper()
	session, err := app.OpenSession(h.vault, []byte(password))
	if err != nil {
		h.t.Fatal(err)
	}
	defer session.Close()
	if err := session.Set(ref, []byte(value)); err != nil {
		h.t.Fatal(err)
	}
}

// project writes rel/envrune.yml and returns the folder.
func (h *harness) project(rel, config string) string {
	h.t.Helper()
	dir := filepath.Join(h.root, rel)
	if err := os.MkdirAll(dir, 0700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "envrune.yml"), []byte(config), 0600); err != nil {
		h.t.Fatal(err)
	}
	return dir
}

// command prepares envrune in dir, with probe on PATH and the password in
// ENVRUNE_PASSWORD, as CI provides it.
func (h *harness) command(dir string, extraEnv []string, args ...string) (*exec.Cmd, *bytes.Buffer) {
	cmd := exec.Command(envruneBin, args...)
	cmd.Dir = dir
	env := []string{"ENVRUNE_VAULT=" + h.vault, "ENVRUNE_PASSWORD=" + password, "NO_COLOR=1", "PATH=" + binDir + string(os.PathListSeparator) + os.Getenv("PATH")}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if upper := strings.ToUpper(name); upper != "PATH" && !strings.HasPrefix(upper, "ENVRUNE_") && upper != "NO_COLOR" {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env, extraEnv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	return cmd, &out
}

func (h *harness) run(dir string, args ...string) (string, int) {
	h.t.Helper()
	return h.runWith(dir, nil, args...)
}

func (h *harness) runWith(dir string, extraEnv []string, args ...string) (string, int) {
	h.t.Helper()
	cmd, out := h.command(dir, extraEnv, args...)
	err := cmd.Run()
	if exit, ok := err.(*exec.ExitError); ok {
		return out.String(), exit.ExitCode()
	}
	if err != nil {
		h.t.Fatalf("envrune %s: %v", strings.Join(args, " "), err)
	}
	return out.String(), 0
}

func expect(t *testing.T, output string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(output, want) {
			t.Fatalf("output misses %q:\n%s", want, output)
		}
	}
}

const devConfig = "version: 1\nproject: demo\ndefault_env: development\nenvironments:\n  development:\n    API_KEY: demo.api-key\n"

func TestRunFindsBareCommandsOnPath(t *testing.T) {
	h := newHarness(t)
	h.set("demo.api-key", "sk-integration")
	dir := h.project("app", devConfig)
	out, code := h.run(dir, "run", "--", "probe", "print", "API_KEY", "pwd")
	if code != 0 {
		t.Fatalf("run = %d:\n%s", code, out)
	}
	expect(t, out, "API_KEY=sk-integration", "pwd="+dir)
}

func TestRunReportsChildFailures(t *testing.T) {
	h := newHarness(t)
	h.set("demo.api-key", "sk-integration")
	dir := h.project("app", devConfig)
	out, code := h.run(dir, "run", "--", "probe", "exit", "3")
	if code != 3 {
		t.Fatalf("exit code = %d, want 3:\n%s", code, out)
	}
	expect(t, out, "exited with code 3")
	out, code = h.run(dir, "run", "--", "envrune-no-such-command")
	if code != 127 {
		t.Fatalf("missing command exit = %d, want 127:\n%s", code, out)
	}
	expect(t, out, "Command not found: envrune-no-such-command")
}

func TestErrorsNameWhatIsMissing(t *testing.T) {
	h := newHarness(t)
	dir := h.project("app", devConfig+"    DATABASE_URL: demo.database-url\n")
	h.set("demo.api-key", "sk-integration")
	out, code := h.run(dir, "run", "--env", "production", "--", "probe")
	if code == 0 {
		t.Fatalf("unknown environment succeeded:\n%s", out)
	}
	expect(t, out, `Environment "production" does not exist; available: development.`)
	out, code = h.run(dir, "run", "--", "probe")
	if code == 0 {
		t.Fatalf("missing reference succeeded:\n%s", out)
	}
	expect(t, out, "demo.database-url (used by DATABASE_URL)")
	if strings.Contains(out, "sk-integration") {
		t.Fatalf("an error printed a secret value:\n%s", out)
	}
}

func TestWrongPasswordAndBusyVaultAreReportedApart(t *testing.T) {
	h := newHarness(t)
	out, code := h.runWith(h.root, []string{"ENVRUNE_PASSWORD=not-the-password"}, "list")
	if code == 0 {
		t.Fatalf("wrong password succeeded:\n%s", out)
	}
	expect(t, out, "master password is wrong")

	lock, err := filelock.Acquire(h.vault)
	if err != nil {
		t.Fatal(err)
	}
	out, code = h.run(h.root, "list")
	lock.Close()
	if code == 0 {
		t.Fatalf("list succeeded while the vault was locked:\n%s", out)
	}
	expect(t, out, fmt.Sprintf("in use by another process (PID %d)", os.Getpid()))
}

func TestRunsShareTheVaultWithWriters(t *testing.T) {
	h := newHarness(t)
	type running struct {
		name string
		cmd  *exec.Cmd
		out  *bytes.Buffer
	}
	var services []running
	started := time.Now()
	for _, name := range []string{"api", "backend", "web"} {
		h.set("demo."+name, "value-"+name)
		dir := h.project(name, fmt.Sprintf("version: 1\nproject: %s\ndefault_env: development\nenvironments:\n  development:\n    TOKEN: demo.%s\n", name, name))
		cmd, out := h.command(dir, nil, "run", "--", "probe", "print", "TOKEN", "sleep", "4s")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		services = append(services, running{name, cmd, out})
	}
	time.Sleep(time.Second)
	out, code := h.run(h.root, "generate", "demo.generated")
	if code != 0 {
		t.Fatalf("generate while three runs were active = %d:\n%s", code, out)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("generate finished after %s; the runs held the vault", elapsed)
	}
	for _, s := range services {
		if err := s.cmd.Wait(); err != nil {
			t.Fatalf("%s: %v\n%s", s.name, err, s.out)
		}
		expect(t, s.out.String(), "TOKEN=value-"+s.name)
	}
	out, _ = h.run(h.root, "list")
	expect(t, out, "demo.api", "demo.generated")
}

func TestNamedCommandsAndUpAcrossProjects(t *testing.T) {
	h := newHarness(t)
	h.set("demo.api-key", "root-value")
	h.set("api.key", "api-value")
	h.set("web.key", "web-value")
	root := h.project("shop", devConfig+`commands:
  hello: probe print API_KEY
  api:
    run: probe print API_KEY sleep 60s
    project: api
  web:
    run: probe print API_KEY heartbeat beat.txt sleep 2s
    project: web
up: [api, web]
`)
	h.project(filepath.Join("shop", "api"), "version: 1\nproject: api\ndefault_env: development\nenvironments:\n  development:\n    API_KEY: api.key\n")
	web := h.project(filepath.Join("shop", "web"), "version: 1\nproject: web\ndefault_env: development\nenvironments:\n  development:\n    API_KEY: web.key\n")

	out, code := h.run(root, "hello")
	if code != 0 {
		t.Fatalf("hello = %d:\n%s", code, out)
	}
	expect(t, out, "API_KEY=root-value")

	started := time.Now()
	out, _ = h.run(root, "up")
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Fatalf("up took %s; the api service was not stopped when web exited:\n%s", elapsed, out)
	}
	expect(t, out, "api | API_KEY=api-value", "web | API_KEY=web-value", "from development in api")

	// The grandchild web started must be gone too.
	beat := filepath.Join(web, "beat.txt")
	before, err := os.Stat(beat)
	if err != nil {
		t.Fatalf("the heartbeat grandchild never ran: %v\n%s", err, out)
	}
	time.Sleep(time.Second)
	after, err := os.Stat(beat)
	if err != nil || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("a process started by the web service still runs after up returned")
	}
}
