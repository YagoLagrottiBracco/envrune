package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

func TestCloudPathsOfAnEnvironment(t *testing.T) {
	f := newFixture(t, "version: 1\nproject: shop\ncloud: acme/shop\nenvironments:\n  production:\n    A: cloud.one\n    B: cloud.two\n"+
		"    C: cloud.acme.shared.production.three\n    D: personal.local\n  staging:\n    A: cloud.one\n")
	config, err := project.Load(f.projectPath)
	if err != nil {
		t.Fatal(err)
	}
	got := map[cloud.Path]bool{}
	for _, p := range cloudPaths(config, "production") {
		got[p] = true
	}
	want := []cloud.Path{{Org: "acme", Project: "shop", Env: "production"}, {Org: "acme", Project: "shared", Env: "production"}}
	if len(got) != len(want) || !got[want[0]] || !got[want[1]] {
		t.Fatalf("cloudPaths = %v", got)
	}
}

// A command asks the server for version numbers before it starts, and
// starts anyway, soon, when the server does not answer.
func TestRunDoesNotWaitForAServerOutOfReach(t *testing.T) {
	asked := make(chan string, 4)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked <- r.URL.Path
		<-release
	}))
	defer srv.Close()
	defer close(release)

	f := newFixture(t, cloudConfig)
	state := `{"server":"` + srv.URL + `","user_id":"alice","tokens":{"access_token":"a.b.c"},"device_id":"d1","device_approved":true,` +
		`"orgs":{"acme":{"id":"org-1","roots":{},"cache":{"shop/production":{"project_id":"p1","environment_id":"e1","payload":{"epoch":1},"fetched_at":"2026-10-01T00:00:00Z"}}}}}`
	if err := f.session.UpdateCloudState(func([]byte) ([]byte, error) { return []byte(state), nil }); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	paths := f.workspace().freshen(f.projectPath, "")
	if waited := time.Since(started); waited > cloud.FreshenCheckTimeout+2*time.Second {
		t.Fatalf("freshen waited %s for a server that did not answer", waited)
	}
	if len(paths) != 1 || paths[0].String() != "acme/shop/production" {
		t.Fatalf("freshen reported %v", paths)
	}
	select {
	case path := <-asked:
		if path != "/api/v1/versions" {
			t.Fatalf("the device asked %s", path)
		}
	default:
		t.Fatal("the device did not ask the server for versions")
	}
	if strings.Contains(f.output(), "Synced") {
		t.Fatalf("nothing was synced, but the output says: %s", f.output())
	}

	// A project with no cloud link asks nothing.
	if err := os.WriteFile(f.projectPath, []byte(baseConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if paths := f.workspace().freshen(f.projectPath, ""); paths != nil || len(asked) != 0 {
		t.Fatalf("a project without a cloud link asked the server: %v", paths)
	}
}
