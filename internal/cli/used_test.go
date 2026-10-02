package cli

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDoctorListsSecretsNobodyUses(t *testing.T) {
	f := newFixture(t, baseConfig)
	for _, ref := range []string{"demo.api-key", "demo.forgotten"} {
		if err := f.session.Set(ref, []byte("a-long-enough-value")); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.session.Link(f.projectPath, "development", "API_KEY", "demo.api-key"); err != nil {
		t.Fatal(err)
	}
	command := []string{"sh", "-c", "true"}
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "exit 0"}
	}
	if code := f.run(append([]string{"run", "--"}, command...)...); code != 0 {
		t.Fatalf("run = %d: %s", code, f.output())
	}
	today := time.Now().Format(time.DateOnly)
	if code := f.run("usage", "demo.api-key"); code != 0 || !strings.Contains(f.output(), "last used it on "+today) {
		t.Fatalf("usage = %d: %s", code, f.output())
	}
	if code := f.run("usage", "demo.forgotten"); code != 0 || !strings.Contains(f.output(), "No command has used it yet") {
		t.Fatalf("usage = %d: %s", code, f.output())
	}

	// Today nothing is old enough; in four months the unlinked, unused one is.
	report := func(now time.Time) string {
		var lines []string
		for _, finding := range f.session.CheckSecrets(f.projectPath, now) {
			lines = append(lines, finding.Message)
		}
		return strings.Join(lines, "\n")
	}
	if now := report(time.Now()); strings.Contains(now, "no command used") {
		t.Fatalf("a new secret is called unused:\n%s", now)
	}
	later := report(time.Now().Add(120 * 24 * time.Hour))
	if !strings.Contains(later, "no project links demo.forgotten, and no command used it in 90 days") || strings.Contains(later, "links demo.api-key") {
		t.Fatalf("doctor in four months:\n%s", later)
	}
}
