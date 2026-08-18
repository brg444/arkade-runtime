package v5

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
		"daily-phone":      "tb1pawzg0ayf2hg3v32pxklq2vzc8vnrly4xun26hp4udm52ffwffncs0t7mep",
		"daily-hardware":   "tb1psz2w9zaejsq45e44lcrpppqwvmrs9hetfnhp5gv77shwpcfysz6s8nvp4t",
		"daily-recovery":   "tb1prtnehy7a4pp084cufv5w49shkxj46xdm77clp8kac076ajkl6dvsdslhpy",
		"savings-phone":    "tb1ptat2893ze3f8v5qgmy8f7kg234t06t22ng07ptepy6k3pfpypy7qrt5sh6",
		"savings-hardware": "tb1p6hetvtpddk0sgpfyv7nmtrh7dfzxqu2l04d26zcrhlyy3pdwrpmsd8sw5g",
		"savings-recovery": "tb1pfewlmeusalmazeggct22a5v8hspvzj2n0ppzuerpdextj0g23g4qwexgt5",
	}
	for key, addrWant := range want {
		kind, claimant, _ := strings.Cut(key, "-")
		addr, _, err := BuildQuarantine(
			"aabbccddeeff00112233445566778899",
			kind, claimant, "mutinynet",
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
