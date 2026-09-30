package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/provider"
)

// fakeService is a provider that serves fixed values and records pushes.
type fakeService struct {
	values []provider.Value
	pushed *[]provider.Value
}

func (fakeService) Name() string                           { return "fake" }
func (fakeService) Flags() []string                        { return []string{"project"} }
func (fakeService) Target(string, provider.Options) string { return "the fake service" }

func (f fakeService) Pull(context.Context, string, provider.Options) ([]provider.Value, provider.Notes, error) {
	out := make([]provider.Value, len(f.values))
	for i, v := range f.values {
		out[i] = provider.Value{Name: v.Name, Value: append([]byte(nil), v.Value...)}
	}
	return out, provider.Notes{"SECRET_THING is write-only there"}, nil
}

func (f fakeService) Push(_ context.Context, _ string, values []provider.Value, _ provider.Options) error {
	for _, v := range values {
		*f.pushed = append(*f.pushed, provider.Value{Name: v.Name, Value: append([]byte(nil), v.Value...)})
	}
	return nil
}

func TestPullShowsChangesAndStoresThemAfterConfirmation(t *testing.T) {
	config := strings.Replace(baseConfig, "  development: {}\n", "  development:\n    SAME: demo.same\n    OLD: demo.old\n    SHARED: team.shared\n", 1)
	f := newFixture(t, config)
	for ref, value := range map[string]string{"demo.same": "same-value", "demo.old": "old-value"} {
		if err := f.session.Set(ref, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	provider.Register(fakeService{values: []provider.Value{
		{Name: "SAME", Value: []byte("same-value")},
		{Name: "OLD", Value: []byte("new-value-from-service")},
		{Name: "FRESH", Value: []byte("fresh-value-from-service")},
		{Name: "SHARED", Value: []byte("team-value")},
		{Name: "bad-name", Value: []byte("x")},
	}})
	f.choices = []string{"y"}
	if code := f.run("pull", "fake"); code != 0 {
		t.Fatalf("pull = %d:\n%s", code, f.output())
	}
	out := f.output()
	for _, want := range []string{
		"SAME                         → demo.same (unchanged)",
		"OLD                          → demo.old (changed)",
		"FRESH                        → demo.fresh.development (new, will be linked)",
		"team reference team.shared", "bad-name is not a valid variable name", "SECRET_THING is write-only",
		"Pulled 2 values",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("pull output misses %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "from-service") {
		t.Fatalf("pull printed a value:\n%s", out)
	}
	value, err := f.session.Reveal(f.projectPath, "demo.old")
	if err != nil || string(value) != "new-value-from-service" {
		t.Fatalf("demo.old = %q, %v", value, err)
	}
	if resolved, err := f.session.Resolve(f.projectPath, ""); err == nil {
		t.Fatalf("team.shared should still be missing, got %v", resolved.Pairs)
	}
	f.choices = nil
	if code := f.run("pull", "fake"); code != 0 || !strings.Contains(f.output(), "The vault already matches") {
		t.Fatalf("second pull = %d:\n%s", code, f.output())
	}
}

func TestPushSendsTheEnvironmentAfterConfirmation(t *testing.T) {
	f := newFixture(t, baseConfig)
	if err := f.session.Set("demo.key", []byte("pushed-value")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "development", "API_KEY", "demo.key"); err != nil {
		t.Fatal(err)
	}
	var pushed []provider.Value
	provider.Register(fakeService{pushed: &pushed})
	f.secrets = []string{"no"}
	if code := f.run("push", "fake"); code != 1 || len(pushed) != 0 {
		t.Fatalf("push without YES = %d, pushed %v", code, pushed)
	}
	f.secrets = []string{"YES"}
	if code := f.run("push", "fake", "--project", "x"); code != 0 {
		t.Fatalf("push = %d:\n%s", code, f.output())
	}
	if len(pushed) != 1 || pushed[0].Name != "API_KEY" || string(pushed[0].Value) != "pushed-value" {
		t.Fatalf("pushed %v", pushed)
	}
	if code := f.run("pull", "github"); code != 2 || !strings.Contains(f.output(), "cannot be read back") {
		t.Fatalf("pull github = %d:\n%s", code, f.output())
	}
}
