package vault

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	crypto "github.com/YagoLagrottiBracco/envrune/internal/crypto"
)

// Version 2 encrypts the payload with a random data key (DEK). The DEK is
// wrapped by the password-derived key and, optionally, by a recovery key, so
// the password can change and a lost password can be recovered without
// re-encrypting under a new data key.
//
//	0:8     magic "ENVRUNE2"
//	8:10    format version (2)
//	10      KDF id (1 = Argon2id)
//	11:20   KDF time, memory KiB, threads
//	20:52   password salt
//	52:76   password wrap nonce
//	76:124  DEK wrapped by the password key
//	124     recovery flag
//	125:149 recovery wrap nonce
//	149:197 DEK wrapped by the recovery key
//	197:221 payload nonce (changes on every write; doubles as the version)
const header2Size = 221

const magic2 = "ENVRUNE2"

var (
	aadPasswordWrap = []byte("envrune dek wrapped by password")
	aadRecoveryWrap = []byte("envrune dek wrapped by recovery key")
)

type headerV2 struct {
	Params        crypto.KDFParams
	Salt          []byte
	PasswordNonce []byte
	PasswordWrap  []byte
	HasRecovery   bool
	RecoveryNonce []byte
	RecoveryWrap  []byte
	Nonce         []byte
}

func (h headerV2) marshal() []byte {
	raw := make([]byte, header2Size)
	copy(raw[:8], magic2)
	binary.BigEndian.PutUint16(raw[8:10], 2)
	raw[10] = 1
	binary.BigEndian.PutUint32(raw[11:15], h.Params.Time)
	binary.BigEndian.PutUint32(raw[15:19], h.Params.MemoryKiB)
	raw[19] = h.Params.Threads
	copy(raw[20:52], h.Salt)
	copy(raw[52:76], h.PasswordNonce)
	copy(raw[76:124], h.PasswordWrap)
	if h.HasRecovery {
		raw[124] = 1
		copy(raw[125:149], h.RecoveryNonce)
		copy(raw[149:197], h.RecoveryWrap)
	}
	copy(raw[197:221], h.Nonce)
	return raw
}

func isV2(raw []byte) bool { return len(raw) >= 8 && string(raw[:8]) == magic2 }

func parseHeaderV2(raw []byte) (headerV2, error) {
	if len(raw) < header2Size || !isV2(raw) || binary.BigEndian.Uint16(raw[8:10]) != 2 || raw[10] != 1 || raw[124] > 1 {
		return headerV2{}, ErrCannotUnlock
	}
	clone := func(b []byte) []byte { return append([]byte(nil), b...) }
	h := headerV2{
		Params:        crypto.KDFParams{Time: binary.BigEndian.Uint32(raw[11:15]), MemoryKiB: binary.BigEndian.Uint32(raw[15:19]), Threads: raw[19], KeyLength: 32},
		Salt:          clone(raw[20:52]),
		PasswordNonce: clone(raw[52:76]),
		PasswordWrap:  clone(raw[76:124]),
		HasRecovery:   raw[124] == 1,
		RecoveryNonce: clone(raw[125:149]),
		RecoveryWrap:  clone(raw[149:197]),
		Nonce:         clone(raw[197:221]),
	}
	if !h.Params.Valid() {
		return headerV2{}, ErrCannotUnlock
	}
	return h, nil
}

func (h *headerV2) wrapPassword(kek, dek []byte) error {
	nonce, wrapped, err := wrap(kek, dek, aadPasswordWrap)
	if err != nil {
		return err
	}
	h.PasswordNonce, h.PasswordWrap = nonce, wrapped
	return nil
}

func (h *headerV2) wrapRecovery(recovery, dek []byte) error {
	nonce, wrapped, err := wrap(recovery, dek, aadRecoveryWrap)
	if err != nil {
		return err
	}
	h.HasRecovery, h.RecoveryNonce, h.RecoveryWrap = true, nonce, wrapped
	return nil
}

func (h headerV2) unwrapPassword(kek []byte) ([]byte, error) {
	dek, err := crypto.Open(kek, h.PasswordNonce, h.PasswordWrap, aadPasswordWrap)
	if err != nil {
		return nil, ErrCannotUnlock
	}
	return dek, nil
}

func (h headerV2) unwrapRecovery(recovery []byte) ([]byte, error) {
	if !h.HasRecovery {
		return nil, ErrNoRecovery
	}
	dek, err := crypto.Open(recovery, h.RecoveryNonce, h.RecoveryWrap, aadRecoveryWrap)
	if err != nil {
		return nil, ErrCannotUnlock
	}
	return dek, nil
}

func wrap(kek, dek, aad []byte) ([]byte, []byte, error) {
	nonce, err := randomBytes(24)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := crypto.Seal(kek, nonce, dek, aad)
	return nonce, wrapped, err
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
