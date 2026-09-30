// Package cloudcrypto implements the client-side cryptography of EnvRune
// Cloud, as designed in docs/cloud-crypto.md: keys, certificates and their
// verification, wrapping environment keys to devices, and sealing values.
// The server only ever stores what this package produces.
package cloudcrypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"strconv"
	"time"
)

var (
	ErrBadSignature = errors.New("the signature does not verify")
	ErrUntrusted    = errors.New("the key is not signed by anyone this organization trusts")
	ErrDecrypt      = errors.New("the data could not be decrypted")
	ErrRollback     = errors.New("the server returned an older version than one already seen")
	ErrMalformed    = errors.New("the data is malformed")
)

// message builds the bytes a signature covers: a domain label, then every
// field with a 4-byte length prefix, so that no two different lists of
// fields, and no two kinds of message, share an encoding.
func message(label string, fields ...[]byte) []byte {
	size := len(label) + 4
	for _, f := range fields {
		size += 4 + len(f)
	}
	out := make([]byte, 0, size)
	out = binary.BigEndian.AppendUint32(out, uint32(len(label)))
	out = append(out, label...)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

func str(s string) []byte { return []byte(s) }

// unix encodes a time as microseconds since 1970, the precision of
// Postgres timestamps, and small enough to stay exact as a JavaScript number
// in the API's JSON (nanoseconds would not).
func unix(t time.Time) []byte { return []byte(strconv.FormatInt(t.UTC().UnixMicro(), 10)) }

func uint64Field(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

func verify(public ed25519.PublicKey, msg, signature []byte) error {
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, msg, signature) {
		return ErrBadSignature
	}
	return nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
