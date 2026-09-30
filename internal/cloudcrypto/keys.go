package cloudcrypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

// RecoveryKey is shown to the user once at sign-up. It decrypts the recovery
// backup, which restores the account key and the recovery age identity on a
// new device.
type RecoveryKey [32]byte

func NewRecoveryKey() (RecoveryKey, error) {
	var k RecoveryKey
	_, err := rand.Read(k[:])
	return k, err
}

func (k RecoveryKey) backupKey(userID string) ([]byte, error) {
	return hkdf.Key(sha256.New, k[:], []byte(userID), "envrune-recovery-backup-v1", chacha20poly1305.KeySize)
}

// Account is a user's long-term signing key. It certifies the user's devices
// and, for admins, the members they add.
type Account struct {
	UserID  string
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func NewAccount(userID string) (*Account, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Account{UserID: userID, Public: public, private: private}, nil
}

func (a *Account) sign(msg []byte) []byte { return ed25519.Sign(a.private, msg) }

// Recovery is what the recovery backup holds.
type Recovery struct {
	Account  *Account
	Identity *age.X25519Identity // the recovery age identity
}

type backupPayload struct {
	AccountKey []byte `json:"account_key"`
	Identity   string `json:"identity"`
}

// SealRecoveryBackup encrypts the account key and the recovery identity
// with a key derived from the recovery key, bound to the user id.
func SealRecoveryBackup(key RecoveryKey, account *Account, identity *age.X25519Identity) ([]byte, error) {
	plain, err := json.Marshal(backupPayload{AccountKey: account.private.Seed(), Identity: identity.String()})
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	k, err := key.backupKey(account.UserID)
	if err != nil {
		return nil, err
	}
	defer wipe(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, message("envrune-recovery-backup-v1", str(account.UserID))), nil
}

// OpenRecoveryBackup reverses SealRecoveryBackup.
func OpenRecoveryBackup(key RecoveryKey, userID string, sealed []byte) (*Recovery, error) {
	k, err := key.backupKey(userID)
	if err != nil {
		return nil, err
	}
	defer wipe(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, ErrMalformed
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], message("envrune-recovery-backup-v1", str(userID)))
	if err != nil {
		return nil, ErrDecrypt
	}
	defer wipe(plain)
	var payload backupPayload
	if json.Unmarshal(plain, &payload) != nil || len(payload.AccountKey) != ed25519.SeedSize {
		return nil, ErrMalformed
	}
	defer wipe(payload.AccountKey)
	identity, err := age.ParseX25519Identity(payload.Identity)
	if err != nil {
		return nil, ErrMalformed
	}
	private := ed25519.NewKeyFromSeed(payload.AccountKey)
	account := &Account{UserID: userID, Public: private.Public().(ed25519.PublicKey), private: private}
	return &Recovery{Account: account, Identity: identity}, nil
}

// Device holds one device's keys. The private parts are stored only in the
// local vault.
type Device struct {
	UserID   string
	DeviceID string
	Identity *age.X25519Identity
	Signing  ed25519.PrivateKey
}

func NewDevice(userID, deviceID string) (*Device, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Device{UserID: userID, DeviceID: deviceID, Identity: identity, Signing: signing}, nil
}

func (d *Device) SigningPublic() ed25519.PublicKey { return d.Signing.Public().(ed25519.PublicKey) }

func (d *Device) sign(msg []byte) []byte { return ed25519.Sign(d.Signing, msg) }

// Fingerprint turns public key material into text two people can compare,
// such as "K7QD-2MXA-P9FE-…": the first 120 bits of SHA-256, in base32.
func Fingerprint(parts ...[]byte) string {
	sum := sha256.Sum256(message("envrune-fingerprint-v1", parts...))
	text := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:15])
	groups := make([]string, 0, len(text)/4)
	for i := 0; i < len(text); i += 4 {
		groups = append(groups, text[i:i+4])
	}
	return strings.Join(groups, "-")
}

// Seed returns the account's private key seed, for the local vault.
func (a *Account) Seed() []byte { return append([]byte(nil), a.private.Seed()...) }

// AccountFromSeed rebuilds an account from Seed.
func AccountFromSeed(userID string, seed []byte) (*Account, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrMalformed
	}
	private := ed25519.NewKeyFromSeed(seed)
	return &Account{UserID: userID, Public: private.Public().(ed25519.PublicKey), private: private}, nil
}

// DeviceFromKeys rebuilds a device from its age identity and signing seed.
func DeviceFromKeys(userID, deviceID, identity string, signingSeed []byte) (*Device, error) {
	id, err := age.ParseX25519Identity(identity)
	if err != nil || len(signingSeed) != ed25519.SeedSize {
		return nil, ErrMalformed
	}
	return &Device{UserID: userID, DeviceID: deviceID, Identity: id, Signing: ed25519.NewKeyFromSeed(signingSeed)}, nil
}

// SigningSeed returns the device's signing key seed, for the local vault.
func (d *Device) SigningSeed() []byte { return append([]byte(nil), d.Signing.Seed()...) }
