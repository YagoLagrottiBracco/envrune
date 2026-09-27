// Package crypto implements Envrune's fixed vault cryptographic primitives.
package crypto

import "errors"

var ErrInvalidParameters = errors.New("invalid cryptographic parameters")

type KDFParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
	KeyLength uint32
}

func DefaultKDFParams(cpuCount int) KDFParams {
	threads := cpuCount
	if threads < 1 {
		threads = 1
	}
	if threads > 4 {
		threads = 4
	}
	return KDFParams{Time: 3, MemoryKiB: 65536, Threads: uint8(threads), KeyLength: 32}
}

func (p KDFParams) Valid() bool {
	return p.Time == 3 && p.MemoryKiB == 65536 && p.Threads >= 1 && p.Threads <= 4 && p.KeyLength == 32
}
