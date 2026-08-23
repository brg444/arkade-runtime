package savings

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func scalarPub(t *testing.T, n byte) *btcec.PublicKey {
	t.Helper()
	var buf [32]byte
	buf[31] = n
	_, pub := btcec.PrivKeyFromBytes(buf[:])
	return pub
}

func TestQuarantineAddressesMatchClientGoldens(t *testing.T) {
	phone, hardware, recovery := scalarPub(t, 3), scalarPub(t, 4), scalarPub(t, 5)
	want := map[string]string{
		"savings-phone":    "tb1pwhdhf7xm4ns689tsf7cy2raw7mxtt54yhf9sa2duvmpj82lnwqps8g6shu",
		"savings-hardware": "tb1ptud88pw5waed36f6r3wwhth7h2j5hskucqvkshrrse8kvuqkve3q92h4fn",
		"savings-recovery": "tb1p7xwlzy07qyttlj9h2n97d3uyjfv8eqf39ec3lqwsgyrztukmuvrsm4kvrn",
	}
	for key, addrWant := range want {
		kind, claimant, _ := strings.Cut(key, "-")
		addr, _, err := BuildQuarantineTemplate(
			"aabbccddeeff00112233445566778899",
			kind, claimant, "mutinynet", Template,
			phone, hardware, recovery,
		)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if addr != addrWant {
			t.Fatalf("%s = %s, want %s", key, addr, addrWant)
		}
	}
}

func TestContextInternalKeyStable(t *testing.T) {
	a, err := ContextInternalKey("aabbccddeeff00112233445566778899", "savings", "hardware")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ContextInternalKey("aabbccddeeff00112233445566778899", "savings", "hardware")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a.SerializeCompressed()) != hex.EncodeToString(b.SerializeCompressed()) {
		t.Fatal("internal key not stable")
	}
}
