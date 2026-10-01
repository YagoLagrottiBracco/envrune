package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auditLog is a chain of three entries with the hashes the database would
// store, computed apart from the client.
const auditLog = `[
{"id":1,"org_id":"org-1","at":"2026-09-30T22:47:26.71+00:00","actor_user_id":"alice","actor_device_id":null,"actor_token_id":null,"action":"org.create","target":"acme","detail":{},"detail_text":"{}","prev_hash":null,"hash":"qqcknOtHSQvsqf7DmFEra4JcESdZY41C0K//xAewBFU="},
{"id":2,"org_id":"org-1","at":"2026-09-30T22:48:00+00:00","actor_user_id":"alice","actor_device_id":"alice-laptop","actor_token_id":null,"action":"secret.write","target":"shop/production/stripe-key","detail":{"epoch":1,"version":1},"detail_text":"{\"epoch\": 1, \"version\": 1}","prev_hash":"qqcknOtHSQvsqf7DmFEra4JcESdZY41C0K//xAewBFU=","hash":"C9d035g+EN/ULYh6sv5mZZCNA8qkONjR9hDj19Ea+78="},
{"id":5,"org_id":"org-1","at":"2026-10-01T09:00:00.000001+00:00","actor_user_id":null,"actor_device_id":null,"actor_token_id":"tok_1","action":"environment.fetch","target":"shop/production","detail":{"epoch":1},"detail_text":"{\"epoch\": 1}","prev_hash":"C9d035g+EN/ULYh6sv5mZZCNA8qkONjR9hDj19Ea+78=","hash":"suFR4TjJj+49i4a7EixLHVarVtIwHVAZQ9gw7CsLEdk="}
]`

func auditServer(t *testing.T, log string) *httptest.Server {
	t.Helper()
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(log), &entries); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/orgs/acme", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "org-1", "slug": "acme", "name": "Acme",
			"roots": []map[string]any{{"user_id": "alice", "account_key": make([]byte, 32)}}})
	})
	mux.HandleFunc("GET /api/v1/orgs/acme/audit", func(w http.ResponseWriter, r *http.Request) {
		page := []json.RawMessage{}
		if r.URL.Query().Get("after") == "0" {
			page = entries
		}
		_ = json.NewEncoder(w).Encode(page)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCloudAuditExportsAndVerifies(t *testing.T) {
	f := signedInFixture(t, auditServer(t, auditLog).URL)
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	if code := f.run("cloud", "audit", "export", "acme", "--output", file); code != 0 {
		t.Fatalf("export = %d: %s", code, f.output())
	}
	if out := f.output(); !strings.Contains(out, "Verified 3 entries") || !strings.Contains(out, "Head: #5 ") {
		t.Fatalf("export said: %s", out)
	}
	raw, err := os.ReadFile(file)
	if err != nil || bytes.Count(raw, []byte("\n")) != 3 {
		t.Fatalf("the export has %d lines: %v", bytes.Count(raw, []byte("\n")), err)
	}
	if code := f.run("cloud", "audit", "export", "acme"); code != 0 || !strings.Contains(f.output(), "still holds entry #5") {
		t.Fatalf("the second export = %d: %s", code, f.output())
	}

	// Verifying needs neither the server nor a session.
	offline := Workspace{Stdout: &f.stdout, Stderr: &f.stderr}
	if code := offline.Execute([]string{"cloud", "audit", "verify", file}); code != 0 || !strings.Contains(f.output(), "3 entries, from 2026-09-30 to 2026-10-01") {
		t.Fatalf("verify = %d: %s", code, f.output())
	}
	older := filepath.Join(t.TempDir(), "older.jsonl")
	lines := bytes.SplitAfter(raw, []byte("\n"))
	if err := os.WriteFile(older, bytes.Join(lines[:2], nil), 0600); err != nil {
		t.Fatal(err)
	}
	if code := f.run("cloud", "audit", "verify", file, "--since", older); code != 0 || !strings.Contains(f.output(), "holds every entry of") {
		t.Fatalf("verify --since = %d: %s", code, f.output())
	}
	if code := f.run("cloud", "audit", "verify", older, "--since", file); code == 0 {
		t.Fatalf("a shorter log continued a longer one: %s", f.output())
	}

	edited := filepath.Join(t.TempDir(), "edited.jsonl")
	if err := os.WriteFile(edited, bytes.Replace(raw, []byte("stripe-key"), []byte("other-key"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if code := f.run("cloud", "audit", "verify", edited); code == 0 || !strings.Contains(f.output(), "entry #2 was changed") {
		t.Fatalf("an edited export = %d: %s", code, f.output())
	}
	if code := f.run("cloud", "audit", "export", "acme", "--since", file); code != 2 {
		t.Fatalf("export --since = %d", code)
	}
}

func TestCloudAuditRefusesAnEditedLog(t *testing.T) {
	f := signedInFixture(t, auditServer(t, strings.Replace(auditLog, `"target":"acme"`, `"target":"evil"`, 1)).URL)
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	if code := f.run("cloud", "audit", "export", "acme", "--output", file); code == 0 || !strings.Contains(f.output(), "entry #1 was changed") {
		t.Fatalf("export = %d: %s", code, f.output())
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("a log that does not verify was written")
	}
}
