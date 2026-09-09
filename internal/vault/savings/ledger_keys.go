package savings

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// LedgerNativeTemplate is a new contract, not enabled by the live registry.
const LedgerNativeTemplate = "phone-ledger-recovery-savings-v1"
const ledgerDomain = "vaulted/ledger-native-savings-v1"

type LedgerAccountOrigin struct {
	Xpub        string   `json:"xpub"`
	Fingerprint string   `json:"fingerprint"`
	Path        []uint32 `json:"path"`
}

type LedgerSavingsKeyContext struct {
	TemplateVersion    string               `json:"templateVersion"`
	Network            string               `json:"network"`
	VaultID            string               `json:"vaultId"`
	PolicyDigest       string               `json:"policyDigest"`
	Phone              LedgerAccountOrigin  `json:"phone"`
	Hardware           LedgerAccountOrigin  `json:"hardware"`
	Recovery           *LedgerAccountOrigin `json:"recovery,omitempty"`
	PhoneDirectP256    string               `json:"phoneDirectP256"`
	VaultCosignerBase  string               `json:"vaultCosignerBase"`
	ArkadeCosignerBase string               `json:"arkadeCosignerBase"`
}

func ledgerHex(value string, size int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != size || value != strings.ToLower(value) {
		return nil, fmt.Errorf("Ledger Savings requires canonical %d-byte hex", size)
	}
	return b, nil
}

// LedgerAccountKey validates metadata; enrollment still must prove device ownership.
func LedgerAccountKey(origin LedgerAccountOrigin, network string) (*hdkeychain.ExtendedKey, error) {
	params, err := networkParams(network)
	if err != nil {
		return nil, err
	}
	if _, err := ledgerHex(origin.Fingerprint, 4); err != nil {
		return nil, err
	}
	coinType := uint32(0)
	if network != "mainnet" {
		coinType = 1
	}
	h := uint32(hdkeychain.HardenedKeyStart)
	if len(origin.Path) != 3 || origin.Path[0] != h+86 || origin.Path[1] != h+coinType || origin.Path[2] < h || origin.Path[2] > h+100 {
		return nil, fmt.Errorf("Ledger Savings requires a BIP86 account origin")
	}
	key, err := hdkeychain.NewKeyFromString(origin.Xpub)
	if err != nil {
		return nil, err
	}
	if key.IsPrivate() || !key.IsForNet(params) || key.String() != origin.Xpub || key.Depth() != 3 || key.ChildIndex() != origin.Path[2] {
		return nil, fmt.Errorf("Ledger Savings requires the matching public account xpub")
	}
	return key, nil
}

func ledgerAccountExpression(origin LedgerAccountOrigin, network string) (string, error) {
	if _, err := LedgerAccountKey(origin, network); err != nil {
		return "", err
	}
	h := uint32(hdkeychain.HardenedKeyStart)
	return fmt.Sprintf("[%s/%d'/%d'/%d']%s", origin.Fingerprint, origin.Path[0]-h, origin.Path[1]-h, origin.Path[2]-h, origin.Xpub), nil
}

func ledgerFields(fields ...string) []byte {
	var out []byte
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		out = append(out, length[:]...)
		out = append(out, field...)
	}
	return out
}

func LedgerSavingsContextDigest(in LedgerSavingsKeyContext) ([]byte, error) {
	if in.TemplateVersion != LedgerNativeTemplate {
		return nil, fmt.Errorf("Ledger Savings template mismatch")
	}
	if _, err := networkParams(in.Network); err != nil {
		return nil, err
	}
	if _, err := ledgerHex(in.VaultID, 16); err != nil {
		return nil, err
	}
	if _, err := ledgerHex(in.PolicyDigest, 32); err != nil {
		return nil, err
	}
	direct, err := ledgerHex(in.PhoneDirectP256, 33)
	if err != nil {
		return nil, err
	}
	if err := parseCanonicalCompressedP256(direct); err != nil {
		return nil, err
	}
	origins := []LedgerAccountOrigin{in.Phone, in.Hardware}
	tier := "standard"
	if in.Recovery != nil {
		origins = append(origins, *in.Recovery)
		tier = "advanced"
	}
	fields := []string{in.TemplateVersion, in.Network, in.VaultID, tier, in.PolicyDigest}
	seen := map[string]bool{}
	for _, origin := range origins {
		key, err := LedgerAccountKey(origin, in.Network)
		if err != nil {
			return nil, err
		}
		pub, err := key.ECPubKey()
		if err != nil {
			return nil, err
		}
		x := pub.SerializeCompressed()[1:]
		if seen[string(x)] || forbiddenXOnly(x) {
			return nil, fmt.Errorf("Ledger Savings authorities must be distinct")
		}
		seen[string(x)] = true
		expression, err := ledgerAccountExpression(origin, in.Network)
		if err != nil {
			return nil, err
		}
		fields = append(fields, expression)
	}
	for _, base := range []string{in.VaultCosignerBase, in.ArkadeCosignerBase} {
		if _, err := ledgerHex(base, 33); err != nil {
			return nil, err
		}
		pub, err := parseCompressed(base)
		if err != nil {
			return nil, err
		}
		x := pub.SerializeCompressed()[1:]
		if seen[string(x)] || forbiddenXOnly(x) {
			return nil, fmt.Errorf("Ledger Savings authorities must be distinct")
		}
		seen[string(x)] = true
	}
	fields = append(fields, in.PhoneDirectP256, in.VaultCosignerBase, in.ArkadeCosignerBase)
	return taggedSHA256(ledgerDomain+"/context", ledgerFields(fields...)), nil
}

// LedgerSavingsChild restricts construction to the initial enrolled coordinates.
func LedgerSavingsChild(parent *hdkeychain.ExtendedKey, branch, index uint32) (*hdkeychain.ExtendedKey, error) {
	if parent == nil || branch > 3 || index != 0 {
		return nil, fmt.Errorf("unenrolled Ledger Savings coordinate")
	}
	step, err := parent.Derive(branch)
	if err != nil {
		return nil, err
	}
	return step.Derive(index)
}

func LedgerSavingsInternalParent(in LedgerSavingsKeyContext) (*hdkeychain.ExtendedKey, error) {
	digest, err := LedgerSavingsContextDigest(in)
	if err != nil {
		return nil, err
	}
	params, err := networkParams(in.Network)
	if err != nil {
		return nil, err
	}
	return hdkeychain.NewExtendedKey(params.HDPublicKeyID[:], numsPub().SerializeCompressed(),
		taggedSHA256(ledgerDomain+"/internal", digest), make([]byte, 4), 0, 0, false), nil
}

// LedgerRecoveryProgramParent only constructs public keys. An authorizer must
// reconstruct and evaluate its named program before deriving the matching secret.
func LedgerRecoveryProgramParent(in LedgerSavingsKeyContext, claimant, cosigner string, script []byte) (*hdkeychain.ExtendedKey, error) {
	digest, err := LedgerSavingsContextDigest(in)
	if err != nil {
		return nil, err
	}
	validClaimant := false
	for _, c := range familyClaimants(in.Recovery != nil) {
		if c == claimant {
			validClaimant = true
		}
	}
	if !validClaimant {
		return nil, fmt.Errorf("unenrolled recovery claimant")
	}
	base := in.VaultCosignerBase
	if cosigner == "arkade" {
		base = in.ArkadeCosignerBase
	} else if cosigner != "vault" {
		return nil, fmt.Errorf("unknown recovery cosigner")
	}
	if len(script) == 0 {
		return nil, fmt.Errorf("recovery program required")
	}
	pub, err := parseCompressed(base)
	if err != nil {
		return nil, err
	}
	tweaked, err := tweakByArkScript(pub, script)
	if err != nil {
		return nil, err
	}
	params, err := networkParams(in.Network)
	if err != nil {
		return nil, err
	}
	return hdkeychain.NewExtendedKey(params.HDPublicKeyID[:], tweaked.SerializeCompressed(),
		taggedSHA256(ledgerDomain+"/program", digest, ledgerFields(claimant, cosigner), arkade.ArkadeScriptHash(script)),
		make([]byte, 4), 0, 0, false), nil
}

// LedgerRecoveryChild uses semantic, disjoint branches for recovery leaves.
// Only index zero is enrolled. It is not a signing capability.
func LedgerRecoveryChild(parent *hdkeychain.ExtendedKey, role string) (*hdkeychain.ExtendedKey, error) {
	branches := map[string]uint32{"claim": 4, "clawback": 6, "cancel": 8, "quarantine": 10}
	branch, ok := branches[role]
	if parent == nil || !ok {
		return nil, fmt.Errorf("unknown Ledger recovery key role")
	}
	step, err := parent.Derive(branch)
	if err != nil {
		return nil, err
	}
	return step.Derive(0)
}

func LedgerRecoveryInternalParent(in LedgerSavingsKeyContext, claimant, stage string) (*hdkeychain.ExtendedKey, error) {
	digest, err := LedgerSavingsContextDigest(in)
	if err != nil {
		return nil, err
	}
	valid := false
	for _, role := range familyClaimants(in.Recovery != nil) {
		valid = valid || role == claimant
	}
	if !valid || (stage != "pending" && stage != "quarantine") {
		return nil, fmt.Errorf("unenrolled recovery stage or claimant")
	}
	params, err := networkParams(in.Network)
	if err != nil {
		return nil, err
	}
	return hdkeychain.NewExtendedKey(params.HDPublicKeyID[:], numsPub().SerializeCompressed(),
		taggedSHA256(ledgerDomain+"/recovery-internal", digest, ledgerFields(claimant, stage)), make([]byte, 4), 0, 0, false), nil
}
