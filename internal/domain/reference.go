// Package domain contains value-safe Envrune domain types.
package domain

import "errors"

var ErrInvalidReference = errors.New("invalid secret reference")

// Reference identifies a secret without carrying its value.
type Reference string

// ParseReference validates the portable, dot-separated reference syntax.
func ParseReference(raw string) (Reference, error) {
	if len(raw) == 0 || len(raw) > 128 {
		return "", ErrInvalidReference
	}
	segmentStart := true
	for _, c := range raw {
		switch {
		case c == '.':
			if segmentStart {
				return "", ErrInvalidReference
			}
			segmentStart = true
		case c >= 'a' && c <= 'z':
			segmentStart = false
		case c >= '0' && c <= '9' || c == '-':
			if segmentStart {
				return "", ErrInvalidReference
			}
			segmentStart = false
		default:
			return "", ErrInvalidReference
		}
	}
	if segmentStart {
		return "", ErrInvalidReference
	}
	return Reference(raw), nil
}

func (r Reference) String() string { return string(r) }
