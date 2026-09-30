package vault

import (
	"encoding/binary"

	crypto "github.com/YagoLagrottiBracco/envrune/internal/crypto"
)

const headerSize = 76

type Header struct {
	Params      crypto.KDFParams
	Salt, Nonce []byte
}

func (h Header) MarshalBinary() []byte {
	raw := make([]byte, headerSize)
	copy(raw[:8], "ENVRUNE1")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	raw[10] = 1
	binary.BigEndian.PutUint32(raw[11:15], h.Params.Time)
	binary.BigEndian.PutUint32(raw[15:19], h.Params.MemoryKiB)
	raw[19] = h.Params.Threads
	copy(raw[20:52], h.Salt)
	copy(raw[52:76], h.Nonce)
	return raw
}

func ParseHeader(raw []byte) (Header, error) {
	if len(raw) != headerSize || string(raw[:8]) != "ENVRUNE1" || binary.BigEndian.Uint16(raw[8:10]) != 1 || raw[10] != 1 {
		return Header{}, ErrCannotUnlock
	}
	h := Header{Params: crypto.KDFParams{Time: binary.BigEndian.Uint32(raw[11:15]), MemoryKiB: binary.BigEndian.Uint32(raw[15:19]), Threads: raw[19], KeyLength: 32}, Salt: append([]byte(nil), raw[20:52]...), Nonce: append([]byte(nil), raw[52:76]...)}
	if !h.Params.Valid() {
		return Header{}, ErrCannotUnlock
	}
	return h, nil
}
