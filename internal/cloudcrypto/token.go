package cloudcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sort"
	"strings"

	"filippo.io/age"
)

const tokenPrefix = "envrune_mt_"

// MachineToken is what a CI system holds: an id and an API secret that the
// server checks, and the private age identity that decrypts the environment
// keys wrapped for it, and the organization's roots, so the CI job verifies
// who wrapped the key and wrote each value without trusting the server.
// Only a hash of the secret reaches the server.
type MachineToken struct {
	ID       string
	Secret   []byte
	Identity *age.X25519Identity
	OrgID    string
	Roots    map[string]ed25519.PublicKey // user id → account key
}

func NewMachineToken(orgID string, roots map[string]ed25519.PublicKey) (*MachineToken, error) {
	id := make([]byte, 12)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return &MachineToken{ID: base64.RawURLEncoding.EncodeToString(id), Secret: secret, Identity: identity, OrgID: orgID, Roots: roots}, nil
}

// String is the token to store as a CI secret, such as ENVRUNE_TOKEN:
// envrune_mt_<id>.<secret>.<age identity>.<org id>~<root user id>:<key>~…
func (t *MachineToken) String() string {
	ids := make([]string, 0, len(t.Roots))
	for id := range t.Roots {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	roots := []string{t.OrgID}
	for _, id := range ids {
		roots = append(roots, id+":"+base64.RawURLEncoding.EncodeToString(t.Roots[id]))
	}
	return tokenPrefix + t.ID + "." + base64.RawURLEncoding.EncodeToString(t.Secret) + "." + t.Identity.String() + "." + strings.Join(roots, "~")
}

// Trust is what the token pins: its organization's roots.
func (t *MachineToken) Trust() Trust { return Trust{OrgID: t.OrgID, Roots: t.Roots} }

// SecretHash is what the server stores to check the API secret.
func (t *MachineToken) SecretHash() []byte { return HashTokenSecret(t.Secret) }

func HashTokenSecret(secret []byte) []byte {
	sum := sha256.Sum256(message("envrune-token-secret-v1", secret))
	return sum[:]
}

// TokenSecretMatches compares a presented secret with a stored hash in
// constant time.
func TokenSecretMatches(secret, storedHash []byte) bool {
	return subtle.ConstantTimeCompare(HashTokenSecret(secret), storedHash) == 1
}

// ParseMachineToken reads a token from String.
func ParseMachineToken(s string) (*MachineToken, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), tokenPrefix)
	if !ok {
		return nil, ErrMalformed
	}
	parts := strings.SplitN(rest, ".", 4)
	if len(parts) != 4 || parts[0] == "" {
		return nil, ErrMalformed
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != 32 {
		return nil, ErrMalformed
	}
	identity, err := age.ParseX25519Identity(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	pins := strings.Split(parts[3], "~")
	if pins[0] == "" || len(pins) < 2 {
		return nil, ErrMalformed
	}
	roots := map[string]ed25519.PublicKey{}
	for _, pin := range pins[1:] {
		user, key, ok := strings.Cut(pin, ":")
		raw, err := base64.RawURLEncoding.DecodeString(key)
		if !ok || user == "" || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, ErrMalformed
		}
		roots[user] = raw
	}
	return &MachineToken{ID: parts[0], Secret: secret, Identity: identity, OrgID: pins[0], Roots: roots}, nil
}
