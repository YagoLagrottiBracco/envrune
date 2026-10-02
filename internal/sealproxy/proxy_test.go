package sealproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

// recorder is a Forwarder that answers for api.example.com and remembers
// what it was asked.
type recorder struct {
	mu       sync.Mutex
	requests []string
	bodies   []string
	fail     error
}

func (r *recorder) Handles(host string) bool { return strings.EqualFold(host, "api.example.com") }

func (r *recorder) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return nil, r.fail
	}
	r.requests = append(r.requests, req.Method+" "+req.URL.String()+" "+req.Header.Get("Authorization"))
	r.bodies = append(r.bodies, string(body))
	return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {"application/json"}, "X-Answer": {"yes"}},
		Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
}

// client is a program configured the way Environment configures one: it
// uses the proxy and trusts the proxy's authority next to extra ones.
func client(t *testing.T, p *Proxy, extra *x509.CertPool) *http.Client {
	t.Helper()
	address, _ := url.Parse(p.Address())
	pool := x509.NewCertPool()
	if extra != nil {
		pool = extra
	}
	pool.AddCert(p.CA())
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(address), TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func TestRequestsToAllowedHostsTakeTheDetour(t *testing.T) {
	fw := &recorder{}
	p, err := Start(fw)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c := client(t, p, nil)

	req, _ := http.NewRequest("POST", "https://api.example.com/v1/charges?n=1", strings.NewReader(`{"token":"envrune_sealed_x"}`))
	req.Header.Set("Authorization", "Bearer envrune_sealed_x")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 || string(body) != `{"ok":true}` || resp.Header.Get("X-Answer") != "yes" {
		t.Fatalf("the program received %d %s", resp.StatusCode, body)
	}
	if len(fw.requests) != 1 || fw.requests[0] != "POST https://api.example.com/v1/charges?n=1 Bearer envrune_sealed_x" || fw.bodies[0] != `{"token":"envrune_sealed_x"}` {
		t.Fatalf("the forwarder was asked %v %v", fw.requests, fw.bodies)
	}
	// A second request on the same connection, and one on a new one.
	for range 2 {
		resp, err := c.Get("https://api.example.com/v1/me")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		c.CloseIdleConnections()
	}
	if len(fw.requests) != 3 {
		t.Fatalf("the forwarder was asked %d times", len(fw.requests))
	}
}

func TestOtherHostsPassThroughUnread(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct "+r.Header.Get("Authorization"))
	}))
	defer other.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "plain") }))
	defer plain.Close()

	fw := &recorder{}
	p, err := Start(fw)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// The program trusts the other server by that server's own certificate:
	// the proxy did not put itself in between.
	pool := x509.NewCertPool()
	pool.AddCert(other.Certificate())
	c := client(t, p, pool)

	req, _ := http.NewRequest("GET", other.URL, nil)
	req.Header.Set("Authorization", "Bearer something-private")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "direct Bearer something-private" || len(resp.TLS.PeerCertificates) == 0 || !resp.TLS.PeerCertificates[0].Equal(other.Certificate()) {
		t.Fatalf("the other host answered %q through another certificate", body)
	}
	if resp, err := c.Get(plain.URL); err != nil {
		t.Fatal(err)
	} else if body, _ := io.ReadAll(resp.Body); string(body) != "plain" {
		t.Fatalf("a plain request answered %q", body)
	}
	if len(fw.requests) != 0 {
		t.Fatalf("the forwarder saw requests to other hosts: %v", fw.requests)
	}
}

func TestRefusalsReachTheProgramAndTheUser(t *testing.T) {
	fw := &recorder{fail: errors.New("you cannot use this environment")}
	p, err := Start(fw)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var told []string
	p.Refused = func(host string, err error) { told = append(told, host+": "+err.Error()) }
	resp, err := client(t, p, nil).Get("https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "envrune: you cannot use this environment") {
		t.Fatalf("the program received %d %s", resp.StatusCode, body)
	}
	if len(told) != 1 || told[0] != "api.example.com: you cannot use this environment" {
		t.Fatalf("the user was told %v", told)
	}
}

func TestEnvironmentPointsAProgramAtTheProxy(t *testing.T) {
	p, err := Start(&recorder{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	system := dir + "/system.pem"
	if err := os.WriteFile(system, []byte("# the system's authorities\n"), 0600); err != nil {
		t.Fatal(err)
	}
	vars, err := p.Environment([]string{"PATH=/bin", "SSL_CERT_FILE=" + system})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vars {
		got[v[0]] = v[1]
	}
	if got["HTTPS_PROXY"] != p.Address() || got["https_proxy"] != p.Address() || got["NODE_USE_ENV_PROXY"] != "1" {
		t.Fatalf("proxy variables: %v", got)
	}
	// The file that replaces a runtime's list holds the system's authorities
	// and this proxy's; the one that adds to it holds only this proxy's.
	bundle, _ := os.ReadFile(got["SSL_CERT_FILE"])
	if !strings.HasPrefix(string(bundle), "# the system's authorities\n") || !strings.Contains(string(bundle), "BEGIN CERTIFICATE") || got["REQUESTS_CA_BUNDLE"] != got["SSL_CERT_FILE"] {
		t.Fatalf("the bundle is %q", bundle)
	}
	added, _ := os.ReadFile(got["NODE_EXTRA_CA_CERTS"])
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(added) || strings.Contains(string(added), "system") {
		t.Fatalf("the added authorities are %q", added)
	}
	p.Close()
	if _, err := os.Stat(got["SSL_CERT_FILE"]); err == nil {
		t.Fatal("the bundle outlived the proxy")
	}
}
