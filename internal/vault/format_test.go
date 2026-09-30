package vault

import (
	"bytes"
	"errors"
	"testing"

	crypto "github.com/envrune/envrune/internal/crypto"
)

func TestHeaderRoundTripPreservesAuthenticatedBytes(t *testing.T) {
	header := Header{Params: crypto.DefaultKDFParams(4), Salt: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 24)}
	raw := header.MarshalBinary()
	parsed, err := ParseHeader(raw)
	if err != nil || !bytes.Equal(parsed.MarshalBinary(), raw) {
		t.Fatalf("header round-trip failed: %v", err)
	}
}

func TestParseHeaderRejectsMalformedInput(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("ENVRUNE0")} {
		if _, err := ParseHeader(raw); !errors.Is(err, ErrCannotUnlock) {
			t.Fatalf("ParseHeader() error = %v", err)
		}
	}
}
