package savings

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

const TransitionSequence = 0xfffffffd

var numsXOnly = mustHex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

type Tree struct {
	Address  string
	PkScript []byte
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func taggedSHA256(tag string, msgs ...[]byte) []byte {
	tagH := sha256.Sum256([]byte(tag))
	h := sha256.New()
	_, _ = h.Write(tagH[:])
	_, _ = h.Write(tagH[:])
	for _, m := range msgs {
		_, _ = h.Write(m)
	}
	return h.Sum(nil)
}

func networkParams(name string) (*chaincfg.Params, error) {
	switch name {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "mutinynet":
		return &arklib.MutinyNetSigNetParams, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", name)
	}
}

func payAddr(pub *btcec.PublicKey, params *chaincfg.Params) (string, []byte, error) {
	script, err := txscript.PayToTaprootScript(pub)
	if err != nil {
		return "", nil, err
	}
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(pub), params)
	if err != nil {
		return "", nil, err
	}
	return addr.EncodeAddress(), script, nil
}

func taprootFromScripts(internal *btcec.PublicKey, scripts [][]byte, network string) (string, []byte, error) {
	params, err := networkParams(network)
	if err != nil {
		return "", nil, err
	}
	leaves := make([]txscript.TapLeaf, len(scripts))
	for i, s := range scripts {
		leaves[i] = txscript.NewBaseTapLeaf(s)
	}
	var merkle []byte
	if len(leaves) == 1 {
		h := leaves[0].TapHash()
		merkle = h[:]
	} else {
		tree := txscript.AssembleTaprootScriptTree(leaves...)
		root := tree.RootNode.TapHash()
		merkle = root[:]
	}
	return payAddr(txscript.ComputeTaprootOutputKey(internal, merkle), params)
}

func parseCompressed(hexPub string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(hexPub)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(raw)
}

func requireDistinctRoleSet(pubs []*btcec.PublicKey, name string) error {
	seen := map[string]struct{}{}
	for _, pub := range pubs {
		if pub == nil {
			return fmt.Errorf("%s key required", name)
		}
		x := schnorr.SerializePubKey(pub)
		hexKey := fmt.Sprintf("%x", x)
		if _, ok := seen[hexKey]; ok {
			return fmt.Errorf("%s keys must be x-only distinct", name)
		}
		seen[hexKey] = struct{}{}
		if forbiddenXOnly(x) {
			return fmt.Errorf("family key is a forbidden point")
		}
	}
	return nil
}

func forbiddenXOnly(x []byte) bool {
	if bytes.Equal(x, numsXOnly) {
		return true
	}
	g, _ := parseCompressed("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	twoG, _ := parseCompressed("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	if g != nil && bytes.Equal(x, schnorr.SerializePubKey(g)) {
		return true
	}
	if twoG != nil && bytes.Equal(x, schnorr.SerializePubKey(twoG)) {
		return true
	}
	return false
}

func checksig(pubs ...*btcec.PublicKey) ([]byte, error) {
	script, err := (&arkscript.MultisigClosure{PubKeys: pubs}).Script()
	if err != nil {
		return nil, err
	}
	return script, nil
}

func pendingDelay(claimant string) uint32 {
	switch claimant {
	case "hardware":
		return program.HardwareRecoveryCSVBlocks
	case "phone":
		return program.PhoneRecoveryCSVBlocks
	default:
		return program.RecoveryCSVBlocks
	}
}

func familyClaimants(hasRecovery bool) []string {
	if hasRecovery {
		return []string{"phone", "hardware", "recovery"}
	}
	return []string{"phone", "hardware"}
}

func quarantineGuardians(claimant string, hasRecovery bool) []string {
	switch claimant {
	case "phone":
		if hasRecovery {
			return []string{"hardware", "recovery"}
		}
		return []string{"hardware"}
	case "hardware":
		if hasRecovery {
			return []string{"phone", "recovery"}
		}
		return []string{"phone"}
	default:
		return []string{"phone", "hardware"}
	}
}

func parseCanonicalCompressedP256(compressed []byte) error {
	if len(compressed) != 33 {
		return fmt.Errorf("compressed p256 key must be 33 bytes")
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		return fmt.Errorf("direct p256 compressed prefix")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return fmt.Errorf("direct p256 point is off-curve")
	}
	if !bytes.Equal(elliptic.MarshalCompressed(elliptic.P256(), x, y), compressed) {
		return fmt.Errorf("direct p256 compressed encoding is not canonical")
	}
	return nil
}

func numsPub() *btcec.PublicKey {
	var x, y btcec.FieldVal
	if x.SetByteSlice(numsXOnly) {
		panic("nums overflow")
	}
	if !btcec.DecompressY(&x, false, &y) {
		panic("nums decompress")
	}
	y.Normalize()
	return btcec.NewPublicKey(&x, &y)
}
