package cloudcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"filippo.io/age"
)

const tokenPrefix = "envrune_mt_"

// MachineToken is what a CI system holds: an id and an API secret that the
// server checks, and the private age identity that decrypts the environment
// keys wrapped for it. Only a hash of the secret reaches the server.
type MachineToken struct {
	ID       string
	Secret   []byte
	Identity *age.X25519Identity
}

func NewMachineToken() (*MachineToken, error) {
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
	return &MachineToken{ID: base64.RawURLEncoding.EncodeToString(id), Secret: secret, Identity: identity}, nil
}

// String is the token to store as a CI secret, such as ENVRUNE_TOKEN.
func (t *MachineToken) String() string {
	return tokenPrefix + t.ID + "." + base64.RawURLEncoding.EncodeToString(t.Secret) + "." + t.Identity.String()
}

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
	parts := strings.SplitN(rest, ".", 3)
	if len(parts) != 3 || parts[0] == "" {
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
	return &MachineToken{ID: parts[0], Secret: secret, Identity: identity}, nil
}
