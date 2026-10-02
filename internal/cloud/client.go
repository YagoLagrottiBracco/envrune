package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultServer is where `envrune login` signs in without --server or
// ENVRUNE_CLOUD_SERVER. Empty until the production server has an address.
var DefaultServer = ""

// APIError is an error answer from the server; its message never holds a
// value.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

var ErrSignedOut = errors.New("not signed in to EnvRune Cloud; run `envrune login`")

// Tokens is a signed-in session.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// Client calls the EnvRune Cloud API.
type Client struct {
	Server string
	HTTP   *http.Client
	Tokens *Tokens
	// Refreshed is called with new tokens after a refresh, to persist them.
	Refreshed func(Tokens) error
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) url(path string, query url.Values) string {
	u := strings.TrimRight(c.Server, "/") + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

// call sends in as JSON and decodes the answer into out. On 401 it refreshes
// the session once and retries.
func (c *Client) call(ctx context.Context, method, path string, query url.Values, in, out any) error {
	if c.Tokens == nil || c.Tokens.AccessToken == "" {
		return ErrSignedOut
	}
	err := c.send(ctx, method, path, query, "Bearer "+c.Tokens.AccessToken, in, out)
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusUnauthorized || c.Tokens.RefreshToken == "" {
		return err
	}
	if err := c.refresh(ctx); err != nil {
		return err
	}
	return c.send(ctx, method, path, query, "Bearer "+c.Tokens.AccessToken, in, out)
}

func (c *Client) refresh(ctx context.Context) error {
	var next Tokens
	if err := c.send(ctx, http.MethodPost, "/cli/refresh", nil, "", map[string]string{"refresh_token": c.Tokens.RefreshToken}, &next); err != nil {
		return ErrSignedOut
	}
	*c.Tokens = next
	if c.Refreshed != nil {
		return c.Refreshed(next)
	}
	return nil
}

func (c *Client) send(ctx context.Context, method, path string, query url.Values, authorization string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		defer wipe(raw)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path, query), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", c.Server, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	defer wipe(raw)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &failure) != nil || failure.Error == "" {
			failure.Error = fmt.Sprintf("the server answered %s", resp.Status)
		}
		return &APIError{Status: resp.StatusCode, Message: failure.Error}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Health checks that the server is an EnvRune Cloud server.
func (c *Client) Health(ctx context.Context) error {
	var h struct {
		Service string `json:"service"`
		API     int    `json:"api"`
	}
	if err := c.send(ctx, http.MethodGet, "/health", nil, "", nil, &h); err != nil {
		return err
	}
	if h.Service != "envrune-cloud" || h.API != 1 {
		return fmt.Errorf("%s is not an EnvRune Cloud server this version understands", c.Server)
	}
	return nil
}

// machineFetch fetches an environment with a machine token.
func (c *Client) machineFetch(ctx context.Context, tokenID string, secret []byte, org, project, env string) (*EnvPayload, error) {
	var out EnvPayload
	auth := "EnvRune-Token " + tokenID + "." + base64URL(secret)
	query := url.Values{"org": {org}, "project": {project}, "env": {env}}
	if err := c.send(ctx, http.MethodGet, "/machine/environment", query, auth, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func asAPIError(err error, target **APIError) bool { return errors.As(err, target) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
