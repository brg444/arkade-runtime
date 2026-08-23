package webauthn

import (
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
	"testing"
)

type testECDSASignature struct {
	R *big.Int
	S *big.Int
}

func TestCompactLowSConvertsFixedWidthAndNormalizes(t *testing.T) {
	t.Parallel()

	n := elliptic.P256().Params().N
	r := big.NewInt(1)
	lowS := big.NewInt(2)
	highS := new(big.Int).Sub(new(big.Int).Set(n), lowS)
	der := mustMarshalDER(t, r, highS)

	got, err := CompactLowS(der)
	if err != nil {
		t.Fatalf("CompactLowS: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("compact length = %d, want 64", len(got))
	}
	if new(big.Int).SetBytes(got[:32]).Cmp(r) != 0 {
		t.Fatalf("r = %x, want %x", got[:32], r)
	}
	if new(big.Int).SetBytes(got[32:]).Cmp(lowS) != 0 {
		t.Fatalf("normalized s = %x, want %x", got[32:], lowS)
	}
}

func TestCompactLowSPreservesLeadingZeroBytesInCompactEncoding(t *testing.T) {
	t.Parallel()

	der := mustMarshalDER(t, big.NewInt(1), big.NewInt(1))
	got, err := CompactLowS(der)
	if err != nil {
		t.Fatalf("CompactLowS: %v", err)
	}
	for i, b := range got[:31] {
		if b != 0 {
			t.Fatalf("r padding byte %d = %x, want 00", i, b)
		}
	}
	if got[31] != 1 || got[63] != 1 {
		t.Fatalf("unexpected fixed-width result: %x", got)
	}
}

func TestCompactLowSRejectsInvalidDERAndScalars(t *testing.T) {
	t.Parallel()

	n := elliptic.P256().Params().N
	tests := []struct {
		name string
		der  []byte
	}{
		{name: "empty", der: nil},
		{name: "truncated sequence", der: []byte{0x30, 0x06, 0x02, 0x01, 0x01}},
		{name: "trailing bytes", der: append(mustMarshalDER(t, big.NewInt(1), big.NewInt(1)), 0x00)},
		{name: "negative r", der: []byte{0x30, 0x06, 0x02, 0x01, 0xff, 0x02, 0x01, 0x01}},
		{name: "negative s", der: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff}},
		{name: "zero r", der: mustMarshalDER(t, big.NewInt(0), big.NewInt(1))},
		{name: "zero s", der: mustMarshalDER(t, big.NewInt(1), big.NewInt(0))},
		{name: "r equal curve order", der: mustMarshalDER(t, n, big.NewInt(1))},
		{name: "s equal curve order", der: mustMarshalDER(t, big.NewInt(1), n)},
		// The redundant 00 on positive integer 1 is not canonical DER.
		{name: "non-minimal r", der: []byte{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01}},
		{name: "wrong top-level type", der: []byte{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := CompactLowS(tc.der); err == nil {
				t.Fatalf("CompactLowS(%x) = %x, want error", tc.der, got)
			}
		})
	}
}

func mustMarshalDER(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	der, err := asn1.Marshal(testECDSASignature{
		R: new(big.Int).Set(r),
		S: new(big.Int).Set(s),
	})
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	return der
}
