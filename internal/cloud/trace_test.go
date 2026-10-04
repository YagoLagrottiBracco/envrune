package cloud

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAServerFailureNamesTheRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/account" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"the request failed"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"only owners may do that"}`))
	}))
	defer srv.Close()
	c := &Client{Server: srv.URL, Tokens: &Tokens{AccessToken: "session"}}

	type seen struct {
		request string
		status  int
		err     error
	}
	var traced []seen
	Trace = func(request string, status int, _ time.Duration, err error) {
		traced = append(traced, seen{request, status, err})
	}
	defer func() { Trace = nil }()

	err := c.call(context.Background(), http.MethodGet, "/account", nil, nil, nil)
	if err == nil || err.Error() != "the request failed (GET /api/v1/account answered 500)" {
		t.Fatalf("a failing server should name the request: %v", err)
	}
	// What the server refuses on purpose already says why.
	err = c.call(context.Background(), http.MethodPost, "/orgs", map[string][]string{"q": {"secret"}}, nil, nil)
	var api *APIError
	if !errors.As(err, &api) || err.Error() != "only owners may do that" {
		t.Fatalf("a refusal keeps the server's message: %v", err)
	}

	if len(traced) != 2 || traced[0].request != "GET /api/v1/account" || traced[0].status != 500 || traced[0].err == nil ||
		traced[1].request != "POST /api/v1/orgs" || traced[1].status != 403 {
		t.Fatalf("every request is traced with its status: %+v", traced)
	}
	for _, s := range traced {
		if strings.Contains(s.request, "secret") || strings.Contains(s.request, "session") {
			t.Fatalf("a trace holds neither the query nor the session: %q", s.request)
		}
	}
}
