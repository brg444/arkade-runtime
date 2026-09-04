package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/brg444/vaulted-guardian/internal/policy"
	"github.com/brg444/vaulted-guardian/internal/vault"
	"github.com/brg444/vaulted-guardian/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

const (
	maxTransitionsPerVaultPerMinute = 10
	transitionRateWindow            = time.Minute
)

// TransitionRequest is initiate or clawback. Claim is never signed here.
// Phone-path transitions also carry a passkey session. Hardware and recovery
// paths must already hold the claimant/guardian BIP340 signature instead —
// those are the stolen-phone exits and cannot require Face ID.
type TransitionRequest struct {
	VaultID string `json:"vaultId"`
	Purpose string `json:"purpose"`
	PSBT    string `json:"psbt"`
	SessionAssertionRequest
}

type TransitionResponse struct {
	SignedPSBT string `json:"signedPsbt"`
	Replay     bool   `json:"replay"`
}

// SignTransition adds the two cosigner signatures after dest and replay checks.
func (s *Service) SignTransition(ctx context.Context, req TransitionRequest) (*TransitionResponse, error) {
	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if purpose != "initiate" && purpose != "clawback" {
		return nil, fmt.Errorf("purpose must be initiate or clawback")
	}
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil {
		return nil, err
	}
	if cred == nil || cred.TemplateVersion != savings.Template {
		return nil, fmt.Errorf("current vault template required")
	}
	ptx, _, err := parseAndVerifyPrevout(req.PSBT)
	if err != nil {
		return nil, err
	}
	if err := validateTransitionPacket(ptx); err != nil {
		return nil, err
	}
	fam, err := s.transitionFamily(cred)
	if err != nil {
		return nil, err
	}
	bound, err := resolveTransitionBinding(fam, cred, purpose, ptx)
	if err != nil {
		return nil, err
	}
	if err := verifyTransitionClaimantSig(ptx, bound); err != nil {
		return nil, err
	}
	if err := s.allowTransition(cred.VaultID); err != nil {
		return nil, err
	}
	if bound.Role == "phone" {
		if _, err := s.authenticatePasskeySession(ctx, passkeyPurposeTransition, req.VaultID, req.SessionAssertionRequest); err != nil {
			return nil, err
		}
	}
	dest := hex.EncodeToString(bound.Dest)
	txid := ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
	vout := int(ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Index)
	sighash, err := transitionSighash(ptx)
	if err != nil {
		return nil, err
	}
	action, stored, err := s.Stores.RecoveryOperations.ApplyRecoveryReplay(policy.RecoverySession{
		VaultID:     req.VaultID,
		Purpose:     purpose,
		InputTxid:   txid,
		InputVout:   vout,
		DestScript:  dest,
		LastSighash: sighash,
	})
	if err != nil {
		return nil, mapLedgerBusy(err)
	}
	if action == policy.ReplayReplay && stored != nil && len(stored.Signature) > 0 {
		if err := sameUnsignedTransition(stored.Signature, ptx); err != nil {
			return nil, err
		}
		return &TransitionResponse{SignedPSBT: string(stored.Signature), Replay: true}, nil
	}
	_, _, rec, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return nil, err
	}
	if bound.VaultTweak == nil || bound.ArkadeTweak == nil {
		return nil, fmt.Errorf("both VaultCosigner and ArkadeCosigner signers are required")
	}
	submitted, err := ptx.B64Encode()
	if err != nil {
		return nil, err
	}
	authorization, err := newSavingsRecoveryAuthorization(
		rec, submitted, schnorr.SerializePubKey(bound.VaultTweak), schnorr.SerializePubKey(bound.ArkadeTweak),
	)
	if err != nil {
		return nil, err
	}
	encoded, err := s.keys.savingsRecoveryAuthorization(ctx, authorization)
	if err != nil {
		return nil, err
	}
	_, _, err = s.Stores.RecoveryOperations.ApplyRecoveryReplay(policy.RecoverySession{
		VaultID:     req.VaultID,
		Purpose:     purpose,
		InputTxid:   txid,
		InputVout:   vout,
		DestScript:  dest,
		LastSighash: sighash,
		Signature:   []byte(encoded),
	})
	if err != nil {
		return nil, mapLedgerBusy(err)
	}
	return &TransitionResponse{SignedPSBT: encoded, Replay: action == policy.ReplayReplay}, nil
}

func validateTransitionPacket(ptx *psbt.Packet) error {
	if ptx == nil || ptx.UnsignedTx == nil {
		return fmt.Errorf("transition dest required")
	}
	if len(ptx.UnsignedTx.TxOut) < 1 {
		return fmt.Errorf("transition dest required")
	}
	if ptx.UnsignedTx.Version != 2 {
		return fmt.Errorf("transaction version must be 2")
	}
	if ptx.UnsignedTx.LockTime != 0 {
		return fmt.Errorf("locktime must be zero")
	}
	if len(ptx.UnsignedTx.TxIn) != 1 || len(ptx.Inputs) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	if ptx.UnsignedTx.TxIn[0].Sequence != savings.TransitionSequence {
		return fmt.Errorf("transition sequence must be 0xfffffffd")
	}
	if ptx.Inputs[0].SighashType != txscript.SigHashDefault {
		return fmt.Errorf("sighash must be SIGHASH_DEFAULT")
	}
	if ptx.Inputs[0].WitnessUtxo == nil {
		return fmt.Errorf("witness utxo required")
	}
	if len(ptx.Inputs[0].TaprootLeafScript) != 1 || ptx.Inputs[0].TaprootLeafScript[0] == nil {
		return fmt.Errorf("exactly one taproot leaf required")
	}
	return nil
}

func transitionSighash(ptx *psbt.Packet) (string, error) {
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value)
	leaf := txscript.NewBaseTapLeaf(ptx.Inputs[0].TaprootLeafScript[0].Script)
	raw, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher),
		txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, leaf,
	)
	if err != nil {
		return "", fmt.Errorf("transition sighash: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func sameUnsignedTransition(stored []byte, current *psbt.Packet) error {
	got, err := psbt.NewFromRawBytes(strings.NewReader(string(stored)), true)
	if err != nil || got == nil || got.UnsignedTx == nil || current == nil || current.UnsignedTx == nil {
		return fmt.Errorf("stored transition does not match the submitted transaction")
	}
	if got.UnsignedTx.TxHash() != current.UnsignedTx.TxHash() {
		return fmt.Errorf("stored transition does not match the submitted transaction")
	}
	return nil
}

func (s *Service) transitionFamily(cred *policy.Credential) (*savings.Family, error) {
	phone, hardware, recovery, vaultBase, arkadeBase, _, err := s.rebuildSavings(cred)
	if err != nil {
		return nil, err
	}
	parsed := parsedRegisterRequest{
		phoneDirectP256: cred.PhoneDirectP256,
		phone:           phone, externalOwner: hardware, recovery: recovery,
		protectionTier: cred.ProtectionTier,
		spendingPolicy: spendingPolicyFromCredential(cred),
	}
	in, err := s.savingsFamilyInput(cred.VaultID, parsed, vaultBase, arkadeBase)
	if err != nil {
		return nil, err
	}
	in.TemplateVersion = cred.TemplateVersion
	in.ServerFreeClawback = cred.TemplateVersion == savings.Template
	_, fam, err := savings.BuildPublicDescriptor(in, cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion)
	if err != nil {
		return nil, err
	}
	return fam, nil
}

type transitionBinding struct {
	Kind        string
	Claimant    string
	Role        string
	Dest        []byte
	VaultTweak  *btcec.PublicKey
	ArkadeTweak *btcec.PublicKey
	Leaf        []byte
	SignerPub   *btcec.PublicKey
}

func resolveTransitionBinding(fam *savings.Family, cred *policy.Credential, purpose string, ptx *psbt.Packet) (*transitionBinding, error) {
	if fam == nil || cred == nil || ptx == nil || ptx.UnsignedTx == nil || len(ptx.UnsignedTx.TxOut) < 1 {
		return nil, fmt.Errorf("transition dest required")
	}
	if ptx.Inputs[0].WitnessUtxo == nil || ptx.Inputs[0].TaprootLeafScript[0] == nil {
		return nil, fmt.Errorf("exactly one taproot leaf required")
	}
	leaf := ptx.Inputs[0].TaprootLeafScript[0].Script
	input := ptx.Inputs[0].WitnessUtxo.PkScript
	dest := ptx.UnsignedTx.TxOut[0].PkScript
	roles, err := recoveryRolePubs(cred)
	if err != nil {
		return nil, err
	}
	claimants := []string{"phone", "hardware", "recovery"}
	if purpose == "initiate" {
		if !bytes.Equal(input, fam.Savings.PkScript) {
			return nil, fmt.Errorf("initiate input is not the rebuilt Savings tree")
		}
		for _, claimant := range claimants {
			pub := roles[claimant]
			pair := fam.Initiate[claimant]
			if pub == nil || pair.Vault == nil || pair.Arkade == nil {
				continue
			}
			want, err := savings.Checksig(pub, pair.Vault, pair.Arkade)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(leaf, want) {
				continue
			}
			key := savings.FamilyKey(claimant)
			pending := fam.Pending[key].PkScript
			if pending == nil || !bytes.Equal(dest, pending) {
				return nil, fmt.Errorf("initiate dest is not the pending tree for this leaf")
			}
			return &transitionBinding{
				Kind: "savings", Claimant: claimant, Role: claimant, Dest: dest,
				VaultTweak: pair.Vault, ArkadeTweak: pair.Arkade, Leaf: leaf, SignerPub: pub,
			}, nil
		}
		return nil, fmt.Errorf("initiate leaf is not a rebuilt Savings recovery tree")
	}
	for _, claimant := range claimants {
		key := savings.FamilyKey(claimant)
		pending := fam.Pending[key].PkScript
		if pending == nil || !bytes.Equal(input, pending) {
			continue
		}
		pair := fam.PendingTweaks[key]
		if pair.Vault == nil || pair.Arkade == nil {
			continue
		}
		for _, guardian := range claimants {
			if guardian == claimant {
				continue
			}
			pub := roles[guardian]
			if pub == nil {
				continue
			}
			want, err := savings.Checksig(pub, pair.Vault, pair.Arkade)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(leaf, want) {
				continue
			}
			quarantine := fam.Quarantine[key].PkScript
			if quarantine == nil || !bytes.Equal(dest, quarantine) {
				return nil, fmt.Errorf("clawback dest is not the quarantine tree for this leaf")
			}
			return &transitionBinding{
				Kind: "savings", Claimant: claimant, Role: guardian, Dest: dest,
				VaultTweak: pair.Vault, ArkadeTweak: pair.Arkade, Leaf: leaf, SignerPub: pub,
			}, nil
		}
	}
	return nil, fmt.Errorf("clawback leaf is not a rebuilt Savings recovery tree")
}

func recoveryRolePubs(cred *policy.Credential) (map[string]*btcec.PublicKey, error) {
	phone, err := btcec.ParsePubKey(cred.PhoneBIP340)
	if err != nil {
		return nil, fmt.Errorf("phone key")
	}
	hardware, err := btcec.ParsePubKey(cred.ExternalOwnerWallet)
	if err != nil {
		return nil, fmt.Errorf("hardware key")
	}
	out := map[string]*btcec.PublicKey{"phone": phone, "hardware": hardware}
	if len(cred.RecoveryKey) > 0 {
		if recovery, err := btcec.ParsePubKey(cred.RecoveryKey); err == nil && recovery != nil {
			out["recovery"] = recovery
		}
	}
	return out, nil
}

func verifyTransitionClaimantSig(ptx *psbt.Packet, bound *transitionBinding) error {
	if bound == nil || bound.SignerPub == nil {
		return fmt.Errorf("transition claimant required")
	}
	if ptx == nil || len(ptx.Inputs) != 1 {
		return fmt.Errorf("exactly one input required")
	}
	wantPub := schnorr.SerializePubKey(bound.SignerPub)
	leaf := txscript.NewBaseTapLeaf(bound.Leaf)
	leafHash := leaf.TapHash()
	var found *psbt.TaprootScriptSpendSig
	for _, sig := range ptx.Inputs[0].TaprootScriptSpendSig {
		if sig == nil {
			continue
		}
		if bytes.Equal(sig.XOnlyPubKey, wantPub) && bytes.Equal(sig.LeafHash, leafHash[:]) {
			found = sig
			break
		}
	}
	if found == nil {
		return fmt.Errorf("transition requires the %s signature before cosigning", bound.Role)
	}
	if found.SigHash != txscript.SigHashDefault {
		return fmt.Errorf("transition claimant sighash")
	}
	if err := vault.VerifySchnorrOnSubmittedTx(ptx, found.Signature, wantPub, bound.Leaf); err != nil {
		return fmt.Errorf("transition claimant signature: %w", err)
	}
	return nil
}

func (s *Service) allowTransition(vaultID string) error {
	now := time.Now()
	if s.EnrollmentNow != nil {
		now = s.EnrollmentNow()
	}
	s.transitionRateMu.Lock()
	defer s.transitionRateMu.Unlock()
	if s.transitionRateHits == nil {
		s.transitionRateHits = make(map[string][]time.Time)
	}
	hits := s.transitionRateHits[vaultID]
	cut := now.Add(-transitionRateWindow)
	kept := hits[:0]
	for _, ts := range hits {
		if ts.After(cut) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= maxTransitionsPerVaultPerMinute {
		s.transitionRateHits[vaultID] = kept
		return fmt.Errorf("too many recovery signatures")
	}
	s.transitionRateHits[vaultID] = append(kept, now)
	return nil
}
