package v5

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

const (
	Schema      = "arkade-vault/v5"
	Template    = "phone-hww-recovery-staged-v5"
	InternalTag = "arkade-vault/v5/internal"
	PopTag      = "arkade-vault/v5/recovery-pop"
)

var numsXOnly = mustHex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func appendText(dst []byte, value, name string) ([]byte, error) {
	if value == "" || value != strings.ToLower(strings.TrimSpace(value)) || value != strings.TrimSpace(value) {
		return nil, fmt.Errorf("%s must be non-empty canonical lowercase", name)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(value)))
	return append(append(dst, lenBuf[:]...), value...), nil
}

func encodeTreeContext(vaultID, kind, claimant string) ([]byte, error) {
	if claimant == "" {
		claimant = "-"
	}
	var dst []byte
	var err error
	if dst, err = appendText(dst, vaultID, "vaultId"); err != nil {
		return nil, err
	}
	if dst, err = appendText(dst, kind, "kind"); err != nil {
		return nil, err
	}
	if dst, err = appendText(dst, claimant, "claimant"); err != nil {
		return nil, err
	}
	return appendText(dst, Template, "templateVersion")
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

// ContextInternalKey is NUMS TapTweaked with tagged_hash(InternalTag, context).
func ContextInternalKey(vaultID, kind, claimant string) (*btcec.PublicKey, error) {
	ctx, err := encodeTreeContext(vaultID, kind, claimant)
	if err != nil {
		return nil, err
	}
	return txscript.ComputeTaprootOutputKey(numsPub(), taggedSHA256(InternalTag, ctx)), nil
}

func networkParams(name string) (*chaincfg.Params, error) {
	switch name {
	case "mutinynet":
		return &arklib.MutinyNetSigNetParams, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
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
