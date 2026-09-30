// Package generator creates secret values without using a predictable source.
package generator

import (
	"crypto/rand"
	"errors"
)

const maxLength = 4096

var ErrInvalidLength = errors.New("invalid generated value length")

// New returns a random URL-safe value of exactly length bytes.
func New(length int) ([]byte, error) {
	if length < 1 || length > maxLength {
		return nil, ErrInvalidLength
	}

	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
	const usable = 256 / len(alphabet) * len(alphabet)

	value := make([]byte, 0, length)
	buffer := make([]byte, length)
	for len(value) < length {
		if _, err := rand.Read(buffer); err != nil {
			for i := range value {
				value[i] = 0
			}
			return nil, err
		}
		for _, random := range buffer {
			if int(random) >= usable {
				continue
			}
			value = append(value, alphabet[int(random)%len(alphabet)])
			if len(value) == length {
				break
			}
		}
	}
	return value, nil
}
