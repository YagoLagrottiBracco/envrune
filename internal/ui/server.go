// Package ui serves a metadata-only dashboard on an IPv4 loopback listener.
package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/web"
)

var ErrServer = errors.New("local interface unavailable")

type MetadataSource interface{ Snapshot() app.DashboardSnapshot }

type Server struct {
	listener         net.Listener
	handler          http.Handler
	http             *http.Server
	origin           string
	source           MetadataSource
	mu               sync.Mutex
	bootstrap        string
	bootstrapExpires time.Time
	session          string
	csrf             string
	closed           bool
	stop             chan struct{}
	stopOnce         sync.Once
}

var pages = template.Must(template.ParseFS(web.Assets, "*.html"))

// New never accepts a hostname or bind address. Port zero selects a free port.
func New(port int, source MetadataSource) (*Server, error) {
	if port < 0 || port > 65535 || source == nil {
		return nil, ErrServer
	}
	bootstrap, err := randomToken()
	if err != nil {
		return nil, ErrServer
	}
	session, err := randomToken()
	if err != nil {
		return nil, ErrServer
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, ErrServer
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, ErrServer
	}
	s := &Server{listener: listener, origin: "http://" + listener.Addr().String(), source: source, bootstrap: bootstrap, bootstrapExpires: time.Now().Add(5 * time.Minute), session: session, csrf: csrf, stop: make(chan struct{})}
	s.handler = http.HandlerFunc(s.serveHTTP)
	s.http = &http.Server{Handler: s.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	return s, nil
}

func randomToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token[:]), nil
}

// URL carries a one-use bootstrap token in the fragment, never an HTTP query.
func (s *Server) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.origin + "/#token=" + s.bootstrap
}

func (s *Server) Serve(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- s.http.Serve(s.listener) }()
	select {
	case <-ctx.Done():
	case <-s.stop:
	case err := <-done:
		s.Close()
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return ErrServer
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.http.Shutdown(shutdown)
	s.Close()
	return nil
}

func (s *Server) lock() {
	s.mu.Lock()
	s.closed = true
	s.bootstrap, s.session, s.csrf = "", "", ""
	s.mu.Unlock()
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *Server) Close() { s.lock(); _ = s.http.Close(); _ = s.listener.Close() }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(remote)
	origin := r.Header.Get("Origin")
	if err != nil || ip == nil || !ip.IsLoopback() || r.Host != s.listener.Addr().String() || (origin != "" && origin != s.origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		deny(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && origin != s.origin {
		deny(w)
		return
	}
	switch r.URL.Path {
	case "/assets/style.css", "/assets/bootstrap.js":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodDenied(w)
			return
		}
		name, contentType := "style.css", "text/css; charset=utf-8"
		if r.URL.Path == "/assets/bootstrap.js" {
			name, contentType = "bootstrap.js", "text/javascript; charset=utf-8"
		}
		content, err := web.Assets.ReadFile(name)
		if err != nil {
			http.Error(w, "Unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(content)
	case "/session":
		if r.Method != http.MethodPost {
			methodDenied(w)
			return
		}
		s.establishSession(w, r)
	case "/":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodDenied(w)
			return
		}
		if !s.authenticated(r) {
			s.render(w, "welcome.html", nil)
			return
		}
		s.mu.Lock()
		csrf := s.csrf
		s.mu.Unlock()
		s.render(w, "dashboard.html", struct {
			Snapshot app.DashboardSnapshot
			CSRF     string
		}{s.source.Snapshot(), csrf})
	case "/lock":
		if r.Method != http.MethodPost {
			methodDenied(w)
			return
		}
		if !s.authenticated(r) {
			deny(w)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if r.ParseForm() != nil {
			deny(w)
			return
		}
		s.mu.Lock()
		valid := tokenEqual(r.PostForm.Get("csrf"), s.csrf)
		s.mu.Unlock()
		if !valid {
			deny(w)
			return
		}
		s.lock()
		http.SetCookie(w, &http.Cookie{Name: "envrune_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		s.render(w, "locked.html", nil)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func (s *Server) establishSession(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		deny(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var input struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		deny(w)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || time.Now().After(s.bootstrapExpires) || !tokenEqual(input.Token, s.bootstrap) {
		deny(w)
		return
	}
	s.bootstrap = ""
	http.SetCookie(w, &http.Cookie{Name: "envrune_session", Value: s.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie("envrune_session")
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.bootstrap == "" && tokenEqual(cookie.Value, s.session)
}

func tokenEqual(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
func deny(w http.ResponseWriter) { http.Error(w, "Forbidden", http.StatusForbidden) }
func methodDenied(w http.ResponseWriter) {
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	var body bytes.Buffer
	if err := pages.ExecuteTemplate(&body, name, data); err != nil {
		http.Error(w, "Unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body.Bytes())
}
