package webauthn

import (
	"strings"
	"testing"
)

func TestDecodeCBORRejectsDuplicateMapKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "integer", raw: []byte{0xa2, 0x01, 0x02, 0x01, 0x03}},
		{name: "text", raw: []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := decodeCBOR(test.raw); err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("duplicate CBOR key accepted: %v", err)
			}
		})
	}
}

func TestDecodeCBORRejectsNonMinimalLengths(t *testing.T) {
	for _, raw := range [][]byte{
		{0x18, 0x00},       // zero encoded with an extra byte
		{0x19, 0x00, 0xff}, // 255 encoded with two extra bytes
		{0xb8, 0x00},       // empty map encoded with an extra byte
	} {
		if _, _, err := decodeCBOR(raw); err == nil || !strings.Contains(err.Error(), "non-minimal") {
			t.Fatalf("non-minimal CBOR accepted (%x): %v", raw, err)
		}
	}
}

func TestDecodeCBORStillAcceptsMinimalBoundaries(t *testing.T) {
	for _, raw := range [][]byte{
		{0x18, 0x18},       // 24
		{0x19, 0x01, 0x00}, // 256
		{0xa1, 0x01, 0x02}, // {1: 2}
	} {
		if _, rest, err := decodeCBOR(raw); err != nil || len(rest) != 0 {
			t.Fatalf("minimal CBOR rejected (%x): rest=%x err=%v", raw, rest, err)
		}
	}
}
