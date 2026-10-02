package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rotationServer answers the two routes guided rotation uses, with one
// departure that exposed two secrets, and records what the CLI marks.
func rotationServer(t *testing.T, statuses map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/orgs/acme", func(w http.ResponseWriter, r *http.Request) {
		var items []map[string]string
		for _, id := range []string{"s1", "s2"} {
			items = append(items, map[string]string{"secret_id": id, "status": statuses[id]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "org-1", "slug": "acme", "name": "Acme",
			"roots": []map[string]string{{"user_id": "alice", "account_key": base64.StdEncoding.EncodeToString(make([]byte, 32))}},
			"projects": []map[string]any{{"id": "p1", "slug": "shop", "environments": []map[string]any{{"id": "e1", "slug": "production", "epoch": 2,
				"secrets": []map[string]any{{"id": "s1", "name": "stripe-key", "current_version": 3}, {"id": "s2", "name": "db-password", "current_version": 2}}}}}},
			"rotation": []map[string]any{{"id": "t1", "reason": "member removed", "subject_user_id": "bob", "created_at": "2026-09-30T22:47:26.710123+00:00",
				"rotation_items": items}},
		})
	})
	mux.HandleFunc("PATCH /api/v1/rotation/{task}/items/{secret}", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Status string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		statuses[r.PathValue("secret")] = b.Status
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func signedInFixture(t *testing.T, server string) *fixture {
	t.Helper()
	f := newFixture(t, cloudConfig)
	state, _ := json.Marshal(map[string]any{"server": server, "user_id": "alice", "tokens": map[string]string{"access_token": "a.b.c"}})
	if err := f.session.UpdateCloudState(func([]byte) ([]byte, error) { return state, nil }); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCloudRotationListsWhatIsStillToReplace(t *testing.T) {
	statuses := map[string]string{"s1": "rotated", "s2": "pending"}
	f := signedInFixture(t, rotationServer(t, statuses).URL)

	if code := f.run("cloud", "rotation", "acme"); code != 0 {
		t.Fatalf("rotation = %d: %s", code, f.output())
	}
	out := f.output()
	for _, want := range []string{"2026-09-30, member removed: bob could read 2 secrets; 1 still to replace.", "acme/shop/production/db-password", "envrune cloud rotation accept"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "stripe-key") {
		t.Errorf("a rotated secret is listed as waiting:\n%s", out)
	}
	if code := f.run("cloud", "rotation", "acme", "--all"); code != 0 || !strings.Contains(f.output(), "acme/shop/production/stripe-key   rotated") {
		t.Fatalf("--all = %d: %s", code, f.output())
	}

	if code := f.run("cloud", "rotation", "accept", "acme/shop/production/db-password"); code != 0 || statuses["s2"] != "accepted" {
		t.Fatalf("accept = %d, status %s: %s", code, statuses["s2"], f.output())
	}
	if code := f.run("cloud", "rotation", "acme"); code != 0 || !strings.Contains(f.output(), "Nothing in acme is waiting") {
		t.Fatalf("after accepting = %d: %s", code, f.output())
	}
	if code := f.run("cloud", "rotation", "accept", "acme/shop/production/db-password"); code == 0 {
		t.Fatalf("accepted twice: %s", f.output())
	}
}

func TestCloudRotationUsage(t *testing.T) {
	f := newFixture(t, cloudConfig)
	for _, args := range [][]string{
		{"cloud", "rotation"},
		{"cloud", "rotation", "accept"},
		{"cloud", "rotation", "accept", "acme/shop/production/x", "--all"},
		{"cloud", "set", "acme/shop/production/x", "--length", "20"},
		{"cloud", "set", "acme/shop/production/x", "--generate", "--length", "many"},
	} {
		if code := f.run(args...); code != 2 {
			t.Errorf("%v = %d: %s", args, code, f.output())
		}
	}
	if code := f.run("cloud", "set", "acme/shop/production/x", "--generate", "--length", "0"); code == 0 {
		t.Errorf("generated an empty value: %s", f.output())
	}
	if code := f.run("cloud", "rotation", "acme"); code == 0 || !strings.Contains(f.output(), "envrune login") {
		t.Errorf("signed out = %d: %s", code, f.output())
	}
}

func TestCloudStatusShowsWhoIsBehind(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/orgs/acme", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "org-1", "slug": "acme", "name": "Acme",
			"roots":    []map[string]string{{"user_id": "alice", "account_key": base64.StdEncoding.EncodeToString(make([]byte, 32))}},
			"projects": []map[string]any{{"id": "p1", "slug": "shop", "environments": []map[string]any{{"id": "e1", "slug": "production", "epoch": 1}}}},
		})
	})
	mux.HandleFunc("GET /api/v1/environments/e1/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"secrets":[{"name":"payments-key","version":7,"written_at":"2020-01-02T14:00:00Z","transition_until":"2020-01-02T15:00:00Z"}],
			"fetches":[{"user_id":"alice","device_id":"laptop","token_id":null,"last_fetch":"2020-01-02T14:05:00Z"},
			           {"user_id":"bob","device_id":"desktop","token_id":null,"last_fetch":"2020-01-01T09:00:00Z"},
			           {"user_id":null,"device_id":null,"token_id":"tok1","last_fetch":"2020-01-02T13:00:00Z"}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f := signedInFixture(t, srv.URL)

	if code := f.run("cloud", "status", "acme/shop/production"); code != 0 {
		t.Fatalf("status = %d: %s", code, f.output())
	}
	out := f.output()
	for _, want := range []string{"payments-key", "alice (laptop)", "has every current value", "bob (desktop)", "token tok1", "stale: its value of payments-key", "2 of 3 have not fetched"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if code := f.run("cloud", "status"); code != 2 {
		t.Errorf("without an environment = %d", code)
	}
	if code := f.run("cloud", "set", "acme/shop/production/x", "--transition", "soon"); code != 2 {
		t.Errorf("a transition that is not a duration = %d", code)
	}
}
