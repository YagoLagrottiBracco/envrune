package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCloudAccountResetAsksFirstAndSaysWhyTheServerRefuses(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/account", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"user_id":"alice","registered":true}`))
	})
	mux.HandleFunc("POST /api/v1/account/reset", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"an account is reset only while it is in no organization; ask an owner or admin of each to remove you first"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f := signedInFixture(t, srv.URL)

	if code := f.run("cloud", "account"); code != 2 || !strings.Contains(f.output(), "cloud account reset") {
		t.Fatalf("account = %d: %s", code, f.output())
	}
	f.choices = []string{"n"}
	if code := f.run("cloud", "account", "reset"); code != 1 || !strings.Contains(f.output(), "Confirmation is required.") {
		t.Fatalf("declined reset = %d: %s", code, f.output())
	}
	f.choices = []string{"y"}
	code := f.run("cloud", "account", "reset")
	out := f.output()
	if code == 0 || !strings.Contains(out, "in no organization") || strings.Contains(out, "Write down this recovery key") {
		t.Fatalf("a refused reset = %d: %s", code, out)
	}
}

func TestCloudRecoveryResetAsksFirstAndNeedsATrustedDevice(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	f := signedInFixture(t, srv.URL)

	if code := f.run("cloud", "recovery"); code != 2 || !strings.Contains(f.output(), "cloud recovery reset") {
		t.Fatalf("recovery = %d: %s", code, f.output())
	}
	f.choices = []string{"n"}
	if code := f.run("cloud", "recovery", "reset"); code != 1 || !strings.Contains(f.output(), "Confirmation is required.") {
		t.Fatalf("declined reset = %d: %s", code, f.output())
	}
	// This vault is signed in but holds no account key: nothing is sent, and
	// no key is shown.
	f.choices = []string{"y"}
	if code := f.run("cloud", "recovery", "reset"); code == 0 || !strings.Contains(f.output(), "waiting for approval") ||
		strings.Contains(f.output(), "Write down this recovery key") {
		t.Fatalf("reset without an account key = %d: %s", code, f.output())
	}
	if requests.Load() != 0 {
		t.Fatalf("%d requests reached the server", requests.Load())
	}
}
