package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
)

func TestVerboseShowsWhichRequestFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"the request failed"}`))
	}))
	t.Cleanup(srv.Close)
	f := signedInFixture(t, srv.URL)

	// Without it, the error alone already names the request.
	if code := f.run("cloud", "rotation", "acme"); code == 0 || !strings.Contains(f.output(), "The request failed (GET /api/v1/orgs/acme answered 500).") {
		t.Fatalf("rotation = %d: %s", code, f.output())
	}
	if strings.Contains(f.output(), "[cloud]") {
		t.Fatalf("requests are printed without --verbose: %s", f.output())
	}

	var trace bytes.Buffer
	traceCloud(&trace)
	t.Cleanup(func() { cloud.Trace = nil })
	if code := f.run("cloud", "rotation", "acme"); code == 0 {
		t.Fatalf("rotation = %d: %s", code, f.output())
	}
	if got := trace.String(); !strings.HasPrefix(got, "[cloud] GET /api/v1/orgs/acme: 500 in ") || strings.Contains(got, "a.b.c") {
		t.Fatalf("the trace should name the request and its status, and never the session: %q", got)
	}
}
