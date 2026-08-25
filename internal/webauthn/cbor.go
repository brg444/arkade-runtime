package webauthn

import (
	"encoding/binary"
	"fmt"
)

const maxCBORBytes = 4096

type cborValue struct {
	kind    cborKind
	intVal  int64
	boolVal bool
	bytes   []byte
	text    string
	mapVal  []cborPair
}

type cborKind int

const (
	cborInt cborKind = iota
	cborBytes
	cborText
	cborMap
	cborBool
)

type cborPair struct {
	key cborValue
	val cborValue
}

func decodeCBOR(in []byte) (cborValue, []byte, error) {
	if len(in) == 0 {
		return cborValue{}, nil, fmt.Errorf("truncated cbor")
	}
	if len(in) > maxCBORBytes {
		return cborValue{}, nil, fmt.Errorf("cbor too large")
	}
	major := in[0] >> 5
	ai := in[0] & 0x1f
	rest := in[1:]
	n, rest, err := decodeCBORLen(ai, rest)
	if err != nil {
		return cborValue{}, nil, err
	}
	switch major {
	case 0:
		return cborValue{kind: cborInt, intVal: int64(n)}, rest, nil
	case 1:
		return cborValue{kind: cborInt, intVal: ^int64(n)}, rest, nil
	case 2:
		if int(n) > len(rest) {
			return cborValue{}, nil, fmt.Errorf("truncated cbor bytes")
		}
		return cborValue{kind: cborBytes, bytes: append([]byte(nil), rest[:n]...)}, rest[n:], nil
	case 3:
		if int(n) > len(rest) {
			return cborValue{}, nil, fmt.Errorf("truncated cbor text")
		}
		return cborValue{kind: cborText, text: string(rest[:n])}, rest[n:], nil
	case 7:
		switch ai {
		case 20:
			return cborValue{kind: cborBool, boolVal: false}, rest, nil
		case 21:
			return cborValue{kind: cborBool, boolVal: true}, rest, nil
		default:
			return cborValue{}, nil, fmt.Errorf("unsupported cbor simple value")
		}
	case 5:
		if n > 16 {
			return cborValue{}, nil, fmt.Errorf("cbor map too large")
		}
		pairs := make([]cborPair, 0, n)
		for i := uint64(0); i < n; i++ {
			k, next, err := decodeCBOR(rest)
			if err != nil {
				return cborValue{}, nil, err
			}
			if k.kind != cborInt && k.kind != cborText {
				return cborValue{}, nil, fmt.Errorf("unsupported cbor map key")
			}
			for _, pair := range pairs {
				if sameCBORMapKey(pair.key, k) {
					return cborValue{}, nil, fmt.Errorf("duplicate cbor map key")
				}
			}
			v, next, err := decodeCBOR(next)
			if err != nil {
				return cborValue{}, nil, err
			}
			pairs = append(pairs, cborPair{key: k, val: v})
			rest = next
		}
		return cborValue{kind: cborMap, mapVal: pairs}, rest, nil
	default:
		return cborValue{}, nil, fmt.Errorf("unsupported cbor major type %d", major)
	}
}

func decodeCBORLen(ai byte, rest []byte) (uint64, []byte, error) {
	switch {
	case ai < 24:
		return uint64(ai), rest, nil
	case ai == 24:
		if len(rest) < 1 {
			return 0, nil, fmt.Errorf("truncated cbor length")
		}
		n := uint64(rest[0])
		if n < 24 {
			return 0, nil, fmt.Errorf("non-minimal cbor length")
		}
		return n, rest[1:], nil
	case ai == 25:
		if len(rest) < 2 {
			return 0, nil, fmt.Errorf("truncated cbor length")
		}
		n := uint64(binary.BigEndian.Uint16(rest[:2]))
		if n <= 0xff {
			return 0, nil, fmt.Errorf("non-minimal cbor length")
		}
		return n, rest[2:], nil
	default:
		return 0, nil, fmt.Errorf("unsupported cbor additional info")
	}
}

func sameCBORMapKey(a, b cborValue) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case cborInt:
		return a.intVal == b.intVal
	case cborText:
		return a.text == b.text
	default:
		return false
	}
}

func (v cborValue) mapInt(key int64) (cborValue, bool) {
	if v.kind != cborMap {
		return cborValue{}, false
	}
	for _, p := range v.mapVal {
		if p.key.kind == cborInt && p.key.intVal == key {
			return p.val, true
		}
	}
	return cborValue{}, false
}

func (v cborValue) mapText(key string) (cborValue, bool) {
	if v.kind != cborMap {
		return cborValue{}, false
	}
	for _, p := range v.mapVal {
		if p.key.kind == cborText && p.key.text == key {
			return p.val, true
		}
	}
	return cborValue{}, false
}

func encodeCBORUnsigned(n uint64) []byte {
	if n < 24 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{24, byte(n)}
	}
	return []byte{25, byte(n >> 8), byte(n)}
}

func encodeCBORNegative(n int64) []byte {
	// n is the CBOR negative value itself (e.g. -1, -7)
	u := uint64(^n)
	out := encodeCBORUnsigned(u)
	out[0] |= 1 << 5
	return out
}

func encodeCBORBytes(b []byte) []byte {
	hdr := encodeCBORUnsigned(uint64(len(b)))
	hdr[0] |= 2 << 5
	return append(hdr, b...)
}

func encodeCBORText(s string) []byte {
	hdr := encodeCBORUnsigned(uint64(len(s)))
	hdr[0] |= 3 << 5
	return append(hdr, s...)
}

func encodeCBORMap(pairs [][]byte) []byte {
	hdr := encodeCBORUnsigned(uint64(len(pairs)))
	hdr[0] |= 5 << 5
	for _, p := range pairs {
		hdr = append(hdr, p...)
	}
	return hdr
}

func encodeCBORBool(v bool) []byte {
	if v {
		return []byte{0xf5}
	}
	return []byte{0xf4}
}
