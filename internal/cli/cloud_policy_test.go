package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudPolicyAppliesAFileOfRules(t *testing.T) {
	var sent string
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/orgs/acme/policy", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sent = string(raw)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/orgs/acme", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "org-1", "slug": "acme", "name": "Acme",
			"roots":  []map[string]string{{"user_id": "alice", "account_key": base64.StdEncoding.EncodeToString(make([]byte, 32))}},
			"policy": []map[string]any{{"environments": "*/production", "deny": []string{"consumer"}}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f := signedInFixture(t, srv.URL)
	dir := t.TempDir()
	file := filepath.Join(dir, "envrune.policy.yml")
	rules := "rules:\n  - environments: \"*/production\"\n    deny: [consumer]\n  - environments: shop/production\n    deny: [admin, maintainer, consumer]\n"
	if err := os.WriteFile(file, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	if code := f.run("cloud", "policy", "set", "acme", file); code != 0 {
		t.Fatalf("policy set = %d: %s", code, f.output())
	}
	if !strings.Contains(sent, `{"environments":"*/production","deny":["consumer"]}`) || !strings.Contains(sent, `"shop/production"`) {
		t.Fatalf("the server was sent %s", sent)
	}
	if code := f.run("cloud", "policy", "show", "acme"); code != 0 || !strings.Contains(f.output(), "*/production") || !strings.Contains(f.output(), "consumer") {
		t.Fatalf("policy show = %d: %s", code, f.output())
	}
	// Mistakes are caught before anything is sent.
	sent = ""
	for name, bad := range map[string]string{
		"an unknown key": "rules:\n  - environments: \"*/production\"\n    allow: [consumer]\n",
		"an owner":       "rules:\n  - environments: \"*/production\"\n    deny: [owner]\n",
		"no environment": "rules:\n  - deny: [consumer]\n",
	} {
		if err := os.WriteFile(file, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if code := f.run("cloud", "policy", "set", "acme", file); code == 0 || sent != "" {
			t.Errorf("%s was applied: %s", name, f.output())
		}
	}
	if code := f.run("cloud", "policy"); code != 2 {
		t.Errorf("policy without arguments = %d", code)
	}
}
