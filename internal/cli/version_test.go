package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVersionPrintsWhatThisBinaryIs(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "1.2.0"
	var stdout, stderr bytes.Buffer
	for _, arg := range []string{"version", "--version"} {
		stdout.Reset()
		if code := Execute([]string{arg}, &stdout, &stderr); code != 0 || stdout.String() != "envrune 1.2.0\n" {
			t.Fatalf("%s = %d: %q %q", arg, code, stdout.String(), stderr.String())
		}
	}
	if code := Execute([]string{"version", "--nope"}, &stdout, &stderr); code != 2 {
		t.Fatalf("a wrong flag = %d", code)
	}
}

func TestVersionCheckAsksOnlyWhenTold(t *testing.T) {
	old, oldURL := Version, latestReleaseURL
	t.Cleanup(func() { Version, latestReleaseURL = old, oldURL })
	asked, tag := 0, "v1.3.0"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		_, _ = w.Write([]byte(`{"tag_name":"` + tag + `"}`))
	}))
	t.Cleanup(srv.Close)
	latestReleaseURL = srv.URL
	Version = "1.2.0"

	run := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := Execute(args, &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	if code, _ := run("version"); code != 0 || asked != 0 {
		t.Fatalf("version = %d, and asked %d times without --check", code, asked)
	}
	if code, out := run("version", "--check"); code != 0 || !strings.Contains(out, "EnvRune 1.3.0 is available") {
		t.Fatalf("an older binary = %d: %s", code, out)
	}
	tag = "v1.2.0"
	if code, out := run("version", "--check"); code != 0 || !strings.Contains(out, "This is the latest release.") {
		t.Fatalf("the latest binary = %d: %s", code, out)
	}
	tag = "nightly"
	if code, out := run("version", "--check"); code != 0 || strings.Contains(out, "is available") {
		t.Fatalf("a strange tag = %d: %s", code, out)
	}
	srv.Close()
	if code, out := run("version", "--check"); code != 1 || !strings.Contains(out, "Could not ask for the latest release") {
		t.Fatalf("no network = %d: %s", code, out)
	}
}

func TestNewerVersionComparesNumbers(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"1.10.0", "1.9.9", true}, {"1.2.0", "1.2.0", false}, {"1.2.0", "1.2.1", false}, {"2.0.0", "1.99.99", true}, {"1.2", "1.1.0", false}, {"1.3.0-rc.1", "1.2.0", false}} {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
