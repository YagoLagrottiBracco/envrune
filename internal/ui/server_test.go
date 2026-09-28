package ui

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/envrune/envrune/internal/app"
)

type dashboardFixture struct{}

func (dashboardFixture) Snapshot() app.DashboardSnapshot {
	return app.DashboardSnapshot{References: []app.ReferenceMetadata{{Name: "openai.personal", Usage: []app.Usage{{ProjectPath: "demo/envrune.yml", Environment: "dev", Variable: "API_KEY"}}}}, Projects: []app.ProjectMetadata{{Name: "<script>alert(1)</script>", Path: "demo/envrune.yml", Environments: []app.EnvironmentMetadata{{Name: "dev", Bindings: []app.BindingMetadata{{Variable: "API_KEY", Reference: "openai.personal", Available: true}}}}}}}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(0, dashboardFixture{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func request(s *Server, method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, s.origin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, r)
	return w
}

func login(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	u, err := url.Parse(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": strings.TrimPrefix(u.Fragment, "token=")})
	w := request(s, "POST", "/session", string(body), nil, s.origin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("login failed: %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie protections missing")
	}
	return cookies[0]
}

func TestDashboardRequiresSessionAndNeverOffersValueEndpoint(t *testing.T) {
	s := newTestServer(t)
	if w := request(s, "GET", "/", "", nil, ""); strings.Contains(w.Body.String(), "openai.personal") {
		t.Fatal("anonymous request exposed metadata")
	}
	cookie := login(t, s)
	w := request(s, "GET", "/", "", cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "openai.personal") || !strings.Contains(w.Body.String(), "API_KEY") {
		t.Fatal("metadata dashboard missing")
	}
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("project name injected executable HTML")
	}
	for _, path := range []string{"/api/secrets/openai.personal", "/values", "/vault", "/env"} {
		if w := request(s, "GET", path, "", cookie, ""); w.Code != http.StatusNotFound {
			t.Fatalf("unexpected endpoint %s", path)
		}
	}
	if w := request(s, "POST", "/", `{"value":"SENTINEL-value"}`, cookie, s.origin); w.Code == 200 || strings.Contains(w.Body.String(), "SENTINEL-value") {
		t.Fatal("mutation accepted or reflected input")
	}
}

func TestHostOriginFetchSiteAndSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	for _, tc := range []struct{ host, origin, site, remote string }{
		{"evil.example", "", "", "127.0.0.1:1234"},
		{strings.TrimPrefix(s.origin, "http://"), "http://evil.example", "", "127.0.0.1:1234"},
		{strings.TrimPrefix(s.origin, "http://"), "", "cross-site", "127.0.0.1:1234"},
		{strings.TrimPrefix(s.origin, "http://"), "", "", "192.0.2.1:1234"},
	} {
		r := httptest.NewRequest("GET", s.origin+"/", nil)
		r.Host = tc.host
		r.RemoteAddr = tc.remote
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		w := httptest.NewRecorder()
		s.handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("unsafe request accepted: %#v", tc)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("missing security headers on error")
		}
	}
	for _, origin := range []string{"", "null", "http://evil.example"} {
		if w := request(s, "POST", "/session", `{"token":"bad"}`, nil, origin); w.Code != http.StatusForbidden {
			t.Fatal("unsafe session request accepted")
		}
	}
}

func TestBootstrapIsOneUseAndLockRequiresCSRF(t *testing.T) {
	s := newTestServer(t)
	bootstrap := s.URL()
	cookie := login(t, s)
	u, _ := url.Parse(bootstrap)
	body, _ := json.Marshal(map[string]string{"token": strings.TrimPrefix(u.Fragment, "token=")})
	if w := request(s, "POST", "/session", string(body), nil, s.origin); w.Code != http.StatusForbidden {
		t.Fatal("bootstrap token reused")
	}
	if w := request(s, "POST", "/lock", "", cookie, s.origin); w.Code != http.StatusForbidden {
		t.Fatal("lock accepted without CSRF")
	}
	w := request(s, "GET", "/", "", cookie, "")
	marker := `name="csrf" value="`
	_, rest, ok := strings.Cut(w.Body.String(), marker)
	if !ok {
		t.Fatal("missing CSRF form field")
	}
	token, _, _ := strings.Cut(rest, `"`)
	r := httptest.NewRequest("POST", s.origin+"/lock", strings.NewReader(url.Values{"csrf": {token}}.Encode()))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Origin", s.origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	locked := httptest.NewRecorder()
	s.handler.ServeHTTP(locked, r)
	if locked.Code != http.StatusOK {
		t.Fatalf("lock failed: %d", locked.Code)
	}
	if w := request(s, "GET", "/", "", cookie, ""); strings.Contains(w.Body.String(), "openai.personal") {
		t.Fatal("session remained usable after lock")
	}
}

func TestListenerIsLoopbackAndStopsOnCancellation(t *testing.T) {
	s := newTestServer(t)
	addr := s.listener.Addr().(*net.TCPAddr)
	if !addr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatal("listener bound outside IPv4 loopback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	response, err := http.Get(s.origin + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
	if _, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
		t.Fatal("listener remains open")
	}
}

func TestRejectsInvalidPorts(t *testing.T) {
	for _, port := range []int{-1, 65536} {
		if s, err := New(port, dashboardFixture{}); err == nil {
			s.Close()
			t.Fatal("invalid port accepted")
		}
	}
}

func TestSessionRejectsMalformedOversizedAndExpiredBootstrap(t *testing.T) {
	s := newTestServer(t)
	for _, body := range []string{`{"token":"wrong"}`, `{"token":"wrong","extra":1}`, `{"token":"wrong"} {}`, strings.Repeat("x", 2048)} {
		w := request(s, "POST", "/session", body, nil, s.origin)
		if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
			t.Fatal("invalid session body accepted")
		}
		if strings.Contains(w.Body.String(), "wrong") {
			t.Fatal("session body reflected")
		}
	}
	s.bootstrapExpires = time.Now().Add(-time.Second)
	u, _ := url.Parse(s.URL())
	body, _ := json.Marshal(map[string]string{"token": strings.TrimPrefix(u.Fragment, "token=")})
	if w := request(s, "POST", "/session", string(body), nil, s.origin); w.Code != http.StatusForbidden {
		t.Fatal("expired bootstrap accepted")
	}
}

func TestHTTPWithRealVaultNeverReturnsSecretOrMasterPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.ev1")
	password := []byte("MASTER-PASSWORD-never-in-HTTP")
	secret := []byte("SECRET-SENTINEL-never-in-HTTP")
	service := app.VaultService{}
	if err := service.Init(path, password, password); err != nil {
		t.Fatal(err)
	}
	if err := service.Set(path, password, "demo.key", secret); err != nil {
		t.Fatal(err)
	}
	dashboard, err := app.OpenDashboard(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboard.Close()
	s, err := New(0, dashboard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cookie := login(t, s)
	for _, endpoint := range []string{"/", "/assets/style.css", "/assets/bootstrap.js", "/values", "/session", "/lock"} {
		w := request(s, "GET", endpoint, "", cookie, "")
		response := w.Body.String() + w.Header().Get("Set-Cookie")
		if strings.Contains(response, string(password)) || strings.Contains(response, string(secret)) {
			t.Fatalf("sensitive value exposed at %s", endpoint)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("cacheable response at %s", endpoint)
		}
	}
}
