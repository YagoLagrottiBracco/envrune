package cloudcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// SecretRecord is one version of one secret as the server stores it.
type SecretRecord struct {
	OrgID, ProjectID, EnvironmentID string
	Name                            string
	Version                         uint64
	Epoch                           uint64
	Nonce                           []byte
	Ciphertext                      []byte
	WriterUserID                    string
	WriterDeviceID                  string
	Signature                       []byte
}

// associatedData binds a ciphertext to its place, so the server cannot
// move it to another secret, environment, version, or epoch.
func (r *SecretRecord) associatedData() []byte {
	return message("envrune-secret-v1", str(r.OrgID), str(r.ProjectID), str(r.EnvironmentID), str(r.Name),
		uint64Field(r.Version), uint64Field(r.Epoch))
}

func (r *SecretRecord) signed() []byte {
	return message("envrune-secret-record-v1", r.associatedData(), r.Nonce, r.Ciphertext, str(r.WriterUserID), str(r.WriterDeviceID))
}

// Seal encrypts version of a secret with the environment key and signs the
// record as this device.
func (d *Device) Seal(k *EnvironmentKey, name string, version uint64, value []byte) (*SecretRecord, error) {
	aead, err := chacha20poly1305.NewX(k.Key)
	if err != nil {
		return nil, err
	}
	r := &SecretRecord{OrgID: k.OrgID, ProjectID: k.ProjectID, EnvironmentID: k.EnvironmentID, Name: name,
		Version: version, Epoch: k.Epoch, WriterUserID: d.UserID, WriterDeviceID: d.DeviceID}
	r.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(r.Nonce); err != nil {
		return nil, err
	}
	r.Ciphertext = aead.Seal(nil, r.Nonce, value, r.associatedData())
	r.Signature = d.sign(r.signed())
	return r, nil
}

// Open checks the writer's signature and decrypts the value. writerKey is
// the signing key of the writer's device, whose certificate the caller
// verified. The caller wipes the value.
func Open(r *SecretRecord, k *EnvironmentKey, writerKey ed25519.PublicKey) ([]byte, error) {
	if err := verify(writerKey, r.signed(), r.Signature); err != nil {
		return nil, err
	}
	if k.Epoch != r.Epoch || k.OrgID != r.OrgID || k.ProjectID != r.ProjectID || k.EnvironmentID != r.EnvironmentID {
		return nil, fmt.Errorf("%w: the record belongs to another environment or epoch", ErrDecrypt)
	}
	aead, err := chacha20poly1305.NewX(k.Key)
	if err != nil {
		return nil, err
	}
	if len(r.Nonce) != aead.NonceSize() {
		return nil, ErrMalformed
	}
	value, err := aead.Open(nil, r.Nonce, r.Ciphertext, r.associatedData())
	if err != nil {
		return nil, ErrDecrypt
	}
	return value, nil
}

// Versions remembers the newest version and epoch seen for each secret, so
// a server cannot serve an older one unnoticed. The CLI persists it in the
// local vault.
type Versions struct {
	mu   sync.Mutex
	seen map[string][2]uint64 // key → {version, epoch}
}

func key(r *SecretRecord) string {
	return r.OrgID + "\x00" + r.ProjectID + "\x00" + r.EnvironmentID + "\x00" + r.Name
}

// Accept records r as seen, or returns ErrRollback when an older version or
// epoch was already seen.
func (v *Versions) Accept(r *SecretRecord) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string][2]uint64{}
	}
	k := key(r)
	if last, ok := v.seen[k]; ok && (r.Version < last[0] || r.Epoch < last[1]) {
		return fmt.Errorf("%w: %s version %d, epoch %d; seen version %d, epoch %d", ErrRollback, r.Name, r.Version, r.Epoch, last[0], last[1])
	}
	v.seen[k] = [2]uint64{r.Version, r.Epoch}
	return nil
}
