package vault

import (
	"encoding/base32"
	"strings"
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// FormatRecoveryKey renders a 32-byte recovery key as dash-separated groups
// that are easy to write down, such as ABCD-EFGH-...
func FormatRecoveryKey(key []byte) string {
	encoded := recoveryEncoding.EncodeToString(key)
	var out strings.Builder
	for i := 0; i < len(encoded); i += 4 {
		if i > 0 {
			out.WriteByte('-')
		}
		out.WriteString(encoded[i:min(i+4, len(encoded))])
	}
	return out.String()
}

// ParseRecoveryKey accepts the formatted key with or without dashes, spaces,
// or lowercase letters.
func ParseRecoveryKey(text string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\r' || r == '\n':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, text)
	key, err := recoveryEncoding.DecodeString(cleaned)
	if err != nil || len(key) != 32 {
		return nil, ErrInvalidRecoveryKey
	}
	return key, nil
}
