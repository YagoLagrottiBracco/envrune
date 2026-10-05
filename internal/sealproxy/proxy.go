// Package sealproxy is the detour a command's requests take when it uses a
// sensitive secret (docs/managed-keys.md). It is an HTTP proxy on the
// loopback interface that lives as long as the command. Requests to hosts a
// sensitive secret allows are read and handed to a Forwarder, which sends
// them through the EnvRune Cloud server; everything else passes through
// untouched and unread.
//
// Reading an HTTPS request means ending the program's TLS connection here.
// Each proxy has its own certificate authority, in memory, which the
// command is told to trust through its environment. What is read this way
// is what the program sent: a placeholder, never the value.
package sealproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Forwarder sends the requests this proxy reads. cloud.Forwarder is one.
type Forwarder interface {
	// Handles reports whether requests to host are to be forwarded.
	Handles(host string) bool
	// Do sends one request, whose URL is absolute, and returns the answer.
	Do(req *http.Request) (*http.Response, error)
}

// Proxy is the detour of one command.
type Proxy struct {
	forwarder Forwarder
	listener  net.Listener
	server    *http.Server
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPEM     []byte
	dir       string // holds the bundle the command trusts

	// upstream says which proxy, if any, a request leaves this computer
	// through: the one the command would have used had it not been pointed
	// here. It is http.ProxyFromEnvironment, so a network that only lets
	// traffic out through its own proxy keeps working.
	upstream func(*http.Request) (*url.URL, error)

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
	// Refused is called when a request could not be forwarded, with the
	// host and the reason, which never holds a value.
	Refused func(host string, err error)
}

// Start listens on the loopback interface and creates this proxy's
// certificate authority.
func Start(forwarder Forwarder) (*Proxy, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "EnvRune, for one command on this computer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{forwarder: forwarder, listener: listener, caCert: cert, caKey: key, leaves: map[string]*tls.Certificate{}, upstream: http.ProxyFromEnvironment,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	p.server = &http.Server{Handler: http.HandlerFunc(p.serve), ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = p.server.Serve(listener) }()
	return p, nil
}

// Address is where the proxy listens, as a proxy URL.
func (p *Proxy) Address() string { return "http://" + p.listener.Addr().String() }

// Close stops the proxy and removes what it wrote.
func (p *Proxy) Close() {
	_ = p.server.Close()
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
	}
}

// systemBundles are where systems keep the certificate authorities they
// trust, as one file.
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // macOS, BSDs
}

// Environment returns the variables that point a program at this proxy and
// make it trust the proxy's certificate authority. inherited is the
// program's environment before them, as NAME=value.
//
// Runtimes differ in how they take extra authorities. Some add a file to
// the ones they trust; others replace their list with the file. For the
// second kind the file holds the system's authorities followed by this
// proxy's, so connections that do not take the detour still verify. Where
// no system bundle is found, only the variables of the first kind are set.
func (p *Proxy) Environment(inherited []string) ([][2]string, error) {
	lookup := func(name string) string {
		for _, entry := range inherited {
			if value, ok := strings.CutPrefix(entry, name+"="); ok {
				return value
			}
		}
		return ""
	}
	dir, err := os.MkdirTemp("", "envrune-ca-")
	if err != nil {
		return nil, err
	}
	p.dir = dir
	only := filepath.Join(dir, "envrune-ca.pem")
	if err := os.WriteFile(only, p.caPEM, 0600); err != nil {
		return nil, err
	}
	address := p.Address()
	out := [][2]string{
		{"HTTPS_PROXY", address}, {"https_proxy", address}, {"HTTP_PROXY", address}, {"http_proxy", address},
		// Node reads the proxy variables only when told to.
		{"NODE_USE_ENV_PROXY", "1"},
	}
	extra := only
	if current := lookup("NODE_EXTRA_CA_CERTS"); current != "" {
		if existing, err := os.ReadFile(current); err == nil {
			extra = filepath.Join(dir, "extra.pem")
			if err := os.WriteFile(extra, append(append(existing, '\n'), p.caPEM...), 0600); err != nil {
				return nil, err
			}
		}
	}
	out = append(out, [2]string{"NODE_EXTRA_CA_CERTS", extra})

	candidates := append([]string{lookup("SSL_CERT_FILE"), lookup("REQUESTS_CA_BUNDLE"), lookup("CURL_CA_BUNDLE")}, systemBundles...)
	for _, candidate := range candidates {
		system, err := os.ReadFile(candidate)
		if candidate == "" || err != nil || len(system) == 0 {
			continue
		}
		bundle := filepath.Join(dir, "bundle.pem")
		if err := os.WriteFile(bundle, append(append(system, '\n'), p.caPEM...), 0600); err != nil {
			return nil, err
		}
		for _, name := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
			out = append(out, [2]string{name, bundle})
		}
		break
	}
	return out, nil
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		p.plain(w, r)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "envrune: not a host and port", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "envrune: cannot take over the connection", http.StatusInternalServerError)
		return
	}
	if port != "443" || !p.forwarder.Handles(host) {
		// Not ours: connect the two ends and read nothing.
		upstream, err := p.dial(r.Context(), r.Host)
		if err != nil {
			http.Error(w, "envrune: could not reach "+r.Host+": "+err.Error(), http.StatusBadGateway)
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() { _, _ = io.Copy(upstream, client); upstream.Close() }()
		go func() { _, _ = io.Copy(client, upstream); client.Close() }()
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	conn := tls.Server(client, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.leaf(host)
		},
	})
	// One connection, served as HTTP until the program closes it.
	inner := &http.Server{ReadHeaderTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.forward(w, r, host)
	})}
	_ = inner.Serve(&oneConn{conn: conn})
}

// forward hands one request read from the program to the Forwarder.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, host string) {
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host, out.RequestURI = "https", host, ""
	resp, err := p.forwarder.Do(out)
	if err != nil {
		if p.Refused != nil {
			p.Refused(host, err)
		}
		http.Error(w, "envrune: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for name, values := range resp.Header {
		switch http.CanonicalHeaderKey(name) {
		case "Connection", "Keep-Alive", "Transfer-Encoding", "Content-Length":
			continue
		}
		w.Header()[name] = values
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// plain passes on a request that is not HTTPS, as any proxy would. A
// sensitive secret is never put into it: the server sends only over HTTPS.
func (p *Proxy) plain(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		http.Error(w, "envrune: this is a proxy; it takes requests for other hosts", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Connection")
	resp, err := (&http.Transport{Proxy: p.upstream}).RoundTrip(out)
	if err != nil {
		http.Error(w, "envrune: could not reach "+r.URL.Host, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for name, values := range resp.Header {
		w.Header()[name] = values
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// dial connects to address, a host and port, for a tunnel this proxy does
// not read: directly, or through the proxy the network requires.
func (p *Proxy) dial(ctx context.Context, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var dialer net.Dialer
	via, err := p.upstream(&http.Request{URL: &url.URL{Scheme: "https", Host: address}})
	if err != nil {
		return nil, err
	}
	if via == nil {
		return dialer.DialContext(ctx, "tcp", address)
	}
	if via.Scheme != "http" && via.Scheme != "https" {
		return nil, errors.New("the network's proxy is a " + via.Scheme + " proxy, which EnvRune cannot use")
	}
	at := via.Host
	if via.Port() == "" {
		at = net.JoinHostPort(via.Hostname(), map[string]string{"http": "80", "https": "443"}[via.Scheme])
	}
	conn, err := dialer.DialContext(ctx, "tcp", at)
	if err != nil {
		return nil, errors.New("the network's proxy could not be reached")
	}
	if via.Scheme == "https" {
		conn = tls.Client(conn, &tls.Config{ServerName: via.Hostname(), MinVersion: tls.VersionTLS12})
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	connect := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: http.Header{}}
	if user := via.User; user != nil {
		password, _ := user.Password()
		connect.SetBasicAuth(user.Username(), password)
		connect.Header.Set("Proxy-Authorization", connect.Header.Get("Authorization"))
		connect.Header.Del("Authorization")
	}
	if err := connect.Write(conn); err != nil {
		conn.Close()
		return nil, errors.New("the network's proxy did not take the request")
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, connect)
	if err != nil {
		conn.Close()
		return nil, errors.New("the network's proxy did not answer")
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, errors.New("the network's proxy answered " + resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	// What the proxy sent after its answer already belongs to the tunnel.
	return &buffered{Conn: conn, reader: reader}, nil
}

// buffered is a connection whose first bytes were already read into reader.
type buffered struct {
	net.Conn
	reader *bufio.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.reader.Read(p) }

// leaf returns a certificate for host signed by this proxy's authority.
func (p *Proxy) leaf(host string) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cert := p.leaves[host]; cert != nil {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	p.leaves[host] = cert
	return cert, nil
}

// CA returns the proxy's certificate authority, for tests and tools.
func (p *Proxy) CA() *x509.Certificate { return p.caCert }

// oneConn is a listener that yields one connection and then waits until
// that connection is closed, so an http.Server serves exactly it.
type oneConn struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConn) Accept() (net.Conn, error) {
	var first net.Conn
	l.once.Do(func() {
		l.done = make(chan struct{})
		first = &closeNotify{Conn: l.conn, closed: l.done}
	})
	if first != nil {
		return first, nil
	}
	<-l.done
	return nil, errors.New("the connection ended")
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

type closeNotify struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
