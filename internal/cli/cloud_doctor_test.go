package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudDoctorSaysTheDatabaseIsBehindAndFails(t *testing.T) {
	database := "behind"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"service": "envrune-cloud", "api": 1, "database": database})
	})
	mux.HandleFunc("GET /api/v1/account", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"user_id": "alice", "registered": false})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f := signedInFixture(t, srv.URL)

	if code := f.run("cloud", "doctor"); code != 1 || !strings.Contains(f.output(), "[ERROR] The server's database is behind the server") {
		t.Fatalf("doctor on a database that is behind = %d: %s", code, f.output())
	}
	database = "ok"
	code := f.run("cloud", "doctor")
	out := f.output()
	if code != 0 || !strings.Contains(out, "[OK] The server's database has the schema the server needs.") ||
		!strings.Contains(out, "[WARNING] This account has no keys yet; run `envrune cloud init`.") {
		t.Fatalf("doctor on a new account = %d: %s", code, out)
	}
	if code := f.run("cloud", "doctor", "extra"); code != 2 {
		t.Fatalf("doctor with an argument = %d", code)
	}
}
