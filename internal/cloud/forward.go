package cloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// A program that uses a sensitive secret holds a placeholder. Its requests
// to the hosts the secret allows go to the server, which puts the value in
// (docs/managed-keys.md). Forwarder is this device's side of that: it knows
// which placeholder stands for which secret, and sends requests as the
// signed-in member.

// PlaceholderPrefix starts every placeholder; the server replaces nothing else.
const PlaceholderPrefix = "envrune_sealed_"

// maxForwardBody bounds a request body, which is read whole so the request
// can be sent again after the session is refreshed.
const maxForwardBody = 32 << 20

// Sealed is a sensitive secret as a command uses it.
type Sealed struct {
	Path          Path
	EnvironmentID string
	Hosts         []string
	// Placeholder is what the program receives in place of the value.
	Placeholder string
}

// ForwardError is the server refusing to forward, or failing to reach the
// service; it is not the service's answer.
type ForwardError struct {
	Status  int
	Message string
}

func (e *ForwardError) Error() string { return e.Message }

// Forwarder forwards a command's requests through the server.
type Forwarder struct {
	client   *Client
	deviceID string
	sealed   []Sealed
}

func newPlaceholder() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return PlaceholderPrefix + hex.EncodeToString(raw), nil
}

// SensitiveNames tells which of the secrets in paths are sensitive ones,
// from what this device learned the last time it saw each organization. It
// reads only the vault, so a command can decide offline whether it needs
// the server.
func (s *Service) SensitiveNames(paths []Path) ([]Path, error) {
	st, err := s.state()
	if err != nil {
		return nil, err
	}
	var out []Path
	for _, path := range paths {
		if o := st.Orgs[path.Org]; o != nil && slices.Contains(o.Sensitive[path.cacheKey()], path.Name) {
			out = append(out, path)
		}
	}
	return out, nil
}

// Forwarder prepares to use the sensitive secrets in paths: it checks with
// the server that each one exists, that an owner or admin signed it for the
// proxy identity this device trusts, and gives each a fresh placeholder.
func (s *Service) Forwarder(ctx context.Context, paths []Path) (*Forwarder, error) {
	st, c, _, err := s.ready()
	if err != nil {
		return nil, err
	}
	f := &Forwarder{client: c, deviceID: st.DeviceID}
	views := map[string]*view{}
	for _, path := range paths {
		v := views[path.Org]
		if v == nil {
			if v, err = s.view(ctx, c, path.Org); err != nil {
				return nil, err
			}
			views[path.Org] = v
		}
		p, e, err := v.environment(path.Project, path.Env)
		if err != nil {
			return nil, err
		}
		me, err := v.member(st.UserID)
		if err != nil {
			return nil, err
		}
		if !me.CanUse(p.Slug, e.Slug) {
			return nil, fmt.Errorf("you may not use %s/%s/%s", path.Org, p.Slug, e.Slug)
		}
		var found *SensitiveInfo
		for _, info := range v.sensitive(p, e, v.pinnedProxy) {
			if info.Name == path.Name {
				found = &info
			}
		}
		switch {
		case found == nil:
			return nil, fmt.Errorf("%s is not a sensitive secret", path)
		case !found.Verified:
			return nil, fmt.Errorf("%s is not signed by an owner or admin for the identity this device trusts: %w", path, ErrUntrustedSensitive)
		}
		placeholder, err := newPlaceholder()
		if err != nil {
			return nil, err
		}
		f.sealed = append(f.sealed, Sealed{Path: path, EnvironmentID: e.ID, Hosts: found.Hosts, Placeholder: placeholder})
	}
	return f, nil
}

// ErrUntrustedSensitive means the server lists a sensitive secret whose
// signature does not verify: its hosts may not be the ones its owner chose.
var ErrUntrustedSensitive = errors.New("refusing to send requests through it")

// Sealed lists the secrets this forwarder serves, with their placeholders.
func (f *Forwarder) Sealed() []Sealed { return slices.Clone(f.sealed) }

// Handles reports whether requests to host are forwarded: whether a secret
// of this command may be sent there.
func (f *Forwarder) Handles(host string) bool {
	host = strings.ToLower(host)
	return slices.ContainsFunc(f.sealed, func(s Sealed) bool { return slices.Contains(s.Hosts, host) })
}

// Do forwards one request of the program, which must be for a host Handles
// accepts, and returns the service's response. A *ForwardError means the
// server did not forward it.
func (f *Forwarder) Do(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	var named []map[string]string
	for _, s := range f.sealed {
		if slices.Contains(s.Hosts, host) {
			named = append(named, map[string]string{"environment_id": s.EnvironmentID, "name": s.Path.Name, "placeholder": s.Placeholder})
		}
	}
	if len(named) == 0 {
		return nil, &ForwardError{Status: http.StatusForbidden, Message: "no sensitive secret of this command may be sent to " + host}
	}
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(io.LimitReader(req.Body, maxForwardBody+1)); err != nil {
			return nil, err
		}
		if len(body) > maxForwardBody {
			return nil, &ForwardError{Status: http.StatusRequestEntityTooLarge, Message: "the request is too large to forward"}
		}
	}
	var headers [][2]string
	for name, values := range req.Header {
		for _, value := range values {
			headers = append(headers, [2]string{name, value})
		}
	}
	encode := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.StdEncoding.EncodeToString(raw)
	}
	target := *req.URL
	target.Scheme, target.Host = "https", req.URL.Host
	send := func() (*http.Response, error) {
		out, err := http.NewRequestWithContext(req.Context(), req.Method, f.client.url("/forward", nil), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		out.Header.Set("Authorization", "Bearer "+f.client.Tokens.AccessToken)
		out.Header.Set("X-EnvRune-Device", f.deviceID)
		out.Header.Set("X-EnvRune-Target", target.String())
		out.Header.Set("X-EnvRune-Headers", encode(headers))
		out.Header.Set("X-EnvRune-Secrets", encode(named))
		if ct := req.Header.Get("Content-Type"); ct != "" {
			out.Header.Set("Content-Type", ct)
		}
		resp, err := f.client.http().Do(out)
		if err != nil {
			return nil, &ForwardError{Status: http.StatusBadGateway, Message: fmt.Sprintf("could not reach %s: %v", f.client.Server, err)}
		}
		return resp, nil
	}
	resp, err := send()
	if err != nil {
		return nil, err
	}
	if refused(resp) && resp.StatusCode == http.StatusUnauthorized && f.client.Tokens.RefreshToken != "" {
		resp.Body.Close()
		if err := f.client.refresh(req.Context()); err != nil {
			return nil, err
		}
		if resp, err = send(); err != nil {
			return nil, err
		}
	}
	if refused(resp) {
		defer resp.Body.Close()
		var failure struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if json.Unmarshal(raw, &failure) != nil || failure.Error == "" {
			failure.Error = "the server answered " + resp.Status
		}
		return nil, &ForwardError{Status: resp.StatusCode, Message: failure.Error}
	}
	resp.Header.Del("X-EnvRune-Forward")
	return resp, nil
}

// refused tells the server's own answer from the service's, which the
// server marks.
func refused(resp *http.Response) bool { return resp.Header.Get("X-EnvRune-Forward") != "upstream" }

// CachedSensitive reports whether path names a sensitive secret, from a
// state the caller already read.
func CachedSensitive(raw []byte, path Path) bool {
	st, err := parseState(raw)
	if err != nil {
		return false
	}
	o := st.Orgs[path.Org]
	return o != nil && slices.Contains(o.Sensitive[path.cacheKey()], path.Name)
}
