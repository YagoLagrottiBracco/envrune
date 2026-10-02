package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"
)

// An organization may name one address to be told about what happens
// (docs/cloud-operations.md). The server sends each event, which is an
// audit entry and so holds no value, signed with a secret that this device
// makes and shows once.

// Webhook is an organization's webhook as its admins see it.
type Webhook struct {
	URL             string     `json:"url"`
	Failures        int        `json:"failures"` // in a row, since the last delivery
	LastError       string     `json:"last_error"`
	LastDeliveredAt *time.Time `json:"last_delivered_at"`
	Waiting         int        `json:"waiting"` // events not sent yet
}

// SetWebhook names the address an organization's events are sent to and
// returns the secret their signatures use, in hex, to give to the receiver.
// It is shown once: the server keeps it and never returns it.
func (s *Service) SetWebhook(ctx context.Context, org, address string) (string, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	if err := c.call(ctx, http.MethodPut, "/orgs/"+url.PathEscape(org)+"/webhook", nil, map[string]any{"url": address, "secret": secret}, nil); err != nil {
		return "", err
	}
	return hex.EncodeToString(secret), nil
}

// ClearWebhook stops sending an organization's events.
func (s *Service) ClearWebhook(ctx context.Context, org string) error {
	_, c, err := s.signedIn()
	if err != nil {
		return err
	}
	return c.call(ctx, http.MethodDelete, "/orgs/"+url.PathEscape(org)+"/webhook", nil, nil, nil)
}

// WebhookStatus returns the organization's webhook, or nil when it has none.
func (s *Service) WebhookStatus(ctx context.Context, org string) (*Webhook, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	var out Webhook
	if err := c.call(ctx, http.MethodGet, "/orgs/"+url.PathEscape(org)+"/webhook", nil, nil, &out); err != nil {
		return nil, err
	}
	if out.URL == "" {
		return nil, nil
	}
	return &out, nil
}

// VerifyWebhook checks an event's signature, as a receiver does: header is
// the X-EnvRune-Signature of the request, body its body, and secret the hex
// string SetWebhook returned.
func VerifyWebhook(secret, header string, body []byte) bool {
	key, err := hex.DecodeString(secret)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hmac.Equal([]byte(header), []byte("sha256="+hex.EncodeToString(mac.Sum(nil))))
}
