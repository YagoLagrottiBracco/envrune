package cloudcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"

	"filippo.io/age"
)

// EnvironmentKey encrypts the values of one project environment during one
// epoch. A new epoch starts on every rotation, such as when a member leaves.
type EnvironmentKey struct {
	OrgID         string
	ProjectID     string
	EnvironmentID string
	Epoch         uint64
	Key           []byte // 32 bytes; wipe with Wipe
}

func NewEnvironmentKey(orgID, projectID, environmentID string, epoch uint64) (*EnvironmentKey, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &EnvironmentKey{OrgID: orgID, ProjectID: projectID, EnvironmentID: environmentID, Epoch: epoch, Key: key}, nil
}

func (k *EnvironmentKey) Wipe() { wipe(k.Key) }

// WrappedKey is an environment key encrypted to one recipient, signed by the
// device that wrapped it.
type WrappedKey struct {
	OrgID, ProjectID, EnvironmentID string
	Epoch                           uint64
	RecipientUserID                 string
	RecipientID                     string
	Wrapped                         []byte // age ciphertext
	WrapperUserID                   string
	WrapperDeviceID                 string
	Signature                       []byte
}

func (w *WrappedKey) signed() []byte {
	return message("envrune-wrapped-key-v1", str(w.OrgID), str(w.ProjectID), str(w.EnvironmentID), uint64Field(w.Epoch),
		str(w.RecipientUserID), str(w.RecipientID), w.Wrapped, str(w.WrapperUserID), str(w.WrapperDeviceID))
}

// Wrap encrypts the key to a recipient whose certificate the caller has
// verified with Trust.VerifyRecipient.
func (d *Device) Wrap(k *EnvironmentKey, recipient *RecipientCertificate) (*WrappedKey, error) {
	r, err := recipient.Recipient()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(k.Key); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	wrapped := &WrappedKey{OrgID: k.OrgID, ProjectID: k.ProjectID, EnvironmentID: k.EnvironmentID, Epoch: k.Epoch,
		RecipientUserID: recipient.UserID, RecipientID: recipient.RecipientID, Wrapped: buf.Bytes(),
		WrapperUserID: d.UserID, WrapperDeviceID: d.DeviceID}
	wrapped.Signature = d.sign(wrapped.signed())
	return wrapped, nil
}

// Unwrap decrypts a wrapped key with identity, after checking that it was
// signed by wrapperKey: the signing key of a device whose certificate the
// caller verified, belonging to a member who may administer the environment.
func Unwrap(w *WrappedKey, identity age.Identity, wrapperKey ed25519.PublicKey) (*EnvironmentKey, error) {
	if err := verify(wrapperKey, w.signed(), w.Signature); err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(w.Wrapped), identity)
	if err != nil {
		return nil, ErrDecrypt
	}
	key, err := io.ReadAll(io.LimitReader(r, 64))
	if err != nil || len(key) != 32 {
		wipe(key)
		return nil, ErrDecrypt
	}
	return &EnvironmentKey{OrgID: w.OrgID, ProjectID: w.ProjectID, EnvironmentID: w.EnvironmentID, Epoch: w.Epoch, Key: key}, nil
}
