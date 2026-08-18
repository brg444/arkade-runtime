package vault

import (
	"bytes"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func testKeys(t *testing.T) (phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner *btcec.PrivateKey, phoneDirect []byte) {
	t.Helper()
	phoneRoutine, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err = btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err = btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultCosigner, err = btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeCosigner, err = btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	return phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, webauthn.CompressedP256(p)
}

func TestTreesAndSavingsExclusion(t *testing.T) {
	phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, phoneDirect := testKeys(t)
	_ = recovery
	op, err := NewOperational(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: vaultCosigner.PubKey(), ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: phoneDirect})
	if err != nil {
		t.Fatal(err)
	}
	if op.Leaves.Routine == nil || op.Leaves.Admin == nil || op.Leaves.PhoneCSV == nil || op.Leaves.HardwareCSV == nil {
		t.Fatal("operational leaves")
	}
	if !op.ContainsTweakedVaultCosigner() {
		t.Fatal("operational must contain tweaked vaultCosigner")
	}
	if !op.ContainsTweakedArkadeCosigner() {
		t.Fatal("operational must contain tweaked arkadeCosigner emulator")
	}

	sv, err := NewSavings(phoneRoutine.PubKey(), externalOwner.PubKey(), vaultCosigner.PubKey(), op.TweakedVaultCosigner, arkadeCosigner.PubKey(), op.TweakedArkadeCosigner)
	if err != nil {
		t.Fatal(err)
	}
	if sv.Leaves.Routine != nil {
		t.Fatal("savings must not have routine leaf")
	}
	if err := sv.AssertNoRoutineCosigners(vaultCosigner.PubKey(), op.TweakedVaultCosigner, arkadeCosigner.PubKey(), op.TweakedArkadeCosigner); err != nil {
		t.Fatal(err)
	}
	if sv.ContainsKey(vaultCosigner.PubKey()) || sv.ContainsKey(op.TweakedVaultCosigner) || sv.ContainsKey(arkadeCosigner.PubKey()) || sv.ContainsKey(op.TweakedArkadeCosigner) {
		t.Fatal("savings contains routine signer key")
	}
	if err := sv.AssertNoRoutineCosigners(); err == nil {
		t.Fatal("empty forbidden list must not prove exclusion")
	}

	forged := *sv
	forged.TweakedVaultCosigner = op.TweakedVaultCosigner
	if forged.ContainsTweakedVaultCosigner() || forged.ContainsKey(op.TweakedVaultCosigner) {
		t.Fatal("TweakedVaultCosigner field must not prove leaf containment")
	}
}

func TestMutinynetTreeUsesPinnedCustomSignetParamsAndExplicitDelays(t *testing.T) {
	phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, phoneDirect := testKeys(t)
	_ = recovery
	opCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 288}
	savingsCSV := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 4032}
	op, err := NewOperationalWithPolicy(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: vaultCosigner.PubKey(), ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: phoneDirect}, "mutinynet", opCSV, savingsCSV, fixtureAuthorizationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(op.Address, "tb1p") || op.Record.Network != "mutinynet" || op.Record.CSV != opCSV {
		t.Fatalf("mutinynet operational descriptor: address=%s network=%s csv=%+v", op.Address, op.Record.Network, op.Record.CSV)
	}
	sv, err := NewSavingsWithPolicy(phoneRoutine.PubKey(), externalOwner.PubKey(), "mutinynet", opCSV, savingsCSV, vaultCosigner.PubKey(), op.TweakedVaultCosigner, arkadeCosigner.PubKey(), op.TweakedArkadeCosigner)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sv.Address, "tb1p") || sv.Record.Network != "mutinynet" || sv.Record.HardwareCSV != savingsCSV {
		t.Fatalf("mutinynet savings descriptor: address=%s network=%s csv=%+v", sv.Address, sv.Record.Network, sv.Record.CSV)
	}
}

func TestVaultRolesAreDistinctByXOnlyIdentity(t *testing.T) {
	phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, phoneDirect := testKeys(t)
	negatedHot := negateTestPub(t, phoneRoutine.PubKey())
	negatedOffline := negateTestPub(t, recovery.PubKey())
	for _, test := range []struct {
		name  string
		build func() error
	}{
		{name: "owner phoneRoutine equals recovery", build: func() error {
			_, err := NewSavings(negatedOffline, recovery.PubKey(), vaultCosigner.PubKey())
			return err
		}},
		{name: "vaultCosigner equals phoneRoutine", build: func() error {
			_, err := NewOperational(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: negatedHot, ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: phoneDirect})
			return err
		}},
		{name: "vaultCosigner equals hardware", build: func() error {
			_, err := NewOperational(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: negateTestPub(t, externalOwner.PubKey()), ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: phoneDirect})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.build(); err == nil || !strings.Contains(err.Error(), "independent") {
				t.Fatalf("collapsed key roles accepted: %v", err)
			}
		})
	}
	if err := requireIndependentXOnly(vaultCosigner.PubKey(), negateTestPub(t, vaultCosigner.PubKey()), phoneRoutine.PubKey(), recovery.PubKey()); err == nil || !strings.Contains(err.Error(), "independent") {
		t.Fatalf("vaultCosigner base and x-only-identical tweaked vaultCosigner accepted: %v", err)
	}
}

func negateTestPub(t *testing.T, pub *btcec.PublicKey) *btcec.PublicKey {
	t.Helper()
	raw := append([]byte(nil), pub.SerializeCompressed()...)
	raw[0] ^= 1
	negated, err := btcec.ParsePubKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return negated
}

func TestAuthorizationScriptExecutesOnCurrentTransaction(t *testing.T) {
	phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, _ := testKeys(t)
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	op, err := NewOperational(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: vaultCosigner.PubKey(), ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: webauthn.CompressedP256(direct)})
	if err != nil {
		t.Fatal(err)
	}
	prevTx, opoint := fakeFund(t, op.PkScript, 80_000)
	dest, _ := txscript.PayToTaprootScript(recovery.PubKey())
	spend, err := BuildRoutineSpend(SpendParams{
		Vault: op, PrevTx: prevTx, PrevOutPoint: opoint,
		RecipientScript: dest, RecipientAmount: 40_000, Fee: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := webauthn.SignDigestLowS(direct, spend.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{sig}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, vaultCosigner.PubKey()); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte{}, sig...)
	bad[0] ^= 1
	if err := SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{bad}); err != nil {
		t.Fatal(err)
	}
	if err := executeRawPacketAuthorization(spend.Packet, vaultCosigner.PubKey()); err == nil {
		t.Fatal("tampered direct signature accepted")
	}
}

func TestNewFromRecordRejectsInvalidKind(t *testing.T) {
	phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, phoneDirect := testKeys(t)
	_ = recovery
	op, err := NewOperational(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: vaultCosigner.PubKey(), ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: phoneDirect})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []Kind{-1, 2, 99} {
		rec := op.Record
		rec.Kind = kind
		got, err := NewFromRecord(rec)
		if err == nil {
			t.Fatalf("invalid kind %d was accepted", kind)
		}
		if got != nil {
			t.Fatalf("invalid kind %d returned a %v vault", kind, got.Record.Kind)
		}
	}
	if _, err := NewFromRecord(op.Record); err != nil {
		t.Fatalf("operational record: %v", err)
	}
	sv, err := NewSavings(phoneRoutine.PubKey(), externalOwner.PubKey(), vaultCosigner.PubKey(), op.TweakedVaultCosigner, arkadeCosigner.PubKey(), op.TweakedArkadeCosigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFromRecord(sv.Record); err != nil {
		t.Fatalf("savings record: %v", err)
	}
}

func TestNewFromRecordDirectP256IsCanonical(t *testing.T) {
	phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, phoneDirect := testKeys(t)
	_ = recovery
	op, err := NewOperational(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: vaultCosigner.PubKey(), ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: phoneDirect})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("empty script and hash derive from DirectP256", func(t *testing.T) {
		rec := op.Record
		rec.AuthScript = nil
		rec.AuthScriptHash = nil
		got, err := NewFromRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Record.AuthScript, op.Record.AuthScript) {
			t.Fatal("derived authorization script")
		}
		if !bytes.Equal(got.Record.AuthScriptHash, op.Record.AuthScriptHash) {
			t.Fatal("derived authorization script hash")
		}
	})

	t.Run("matching supplied script and hash stored as derived", func(t *testing.T) {
		got, err := NewFromRecord(op.Record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Record.AuthScript, op.Record.AuthScript) {
			t.Fatal("matching script not stored")
		}
		if !bytes.Equal(got.Record.AuthScriptHash, op.Record.AuthScriptHash) {
			t.Fatal("matching hash not stored")
		}
	})

	t.Run("mismatched auth script rejected", func(t *testing.T) {
		rec := op.Record
		rec.AuthScript = append([]byte{}, rec.AuthScript...)
		rec.AuthScript[len(rec.AuthScript)-1] ^= 0x01
		if _, err := NewFromRecord(rec); err == nil {
			t.Fatal("mismatched auth script accepted")
		}
	})

	t.Run("mismatched auth script hash rejected", func(t *testing.T) {
		rec := op.Record
		rec.AuthScriptHash = append([]byte{}, rec.AuthScriptHash...)
		rec.AuthScriptHash[0] ^= 0x01
		if _, err := NewFromRecord(rec); err == nil {
			t.Fatal("mismatched auth script hash accepted")
		}
	})

	t.Run("empty script with mismatched hash rejected", func(t *testing.T) {
		rec := op.Record
		rec.AuthScript = nil
		rec.AuthScriptHash = append([]byte{}, rec.AuthScriptHash...)
		rec.AuthScriptHash[0] ^= 0x01
		if _, err := NewFromRecord(rec); err == nil {
			t.Fatal("mismatched hash with empty script accepted")
		}
	})

	t.Run("matching script with empty hash stores derived hash", func(t *testing.T) {
		rec := op.Record
		rec.AuthScriptHash = nil
		got, err := NewFromRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Record.AuthScript, op.Record.AuthScript) {
			t.Fatal("matching script not stored")
		}
		if !bytes.Equal(got.Record.AuthScriptHash, op.Record.AuthScriptHash) {
			t.Fatal("derived hash not stored")
		}
	})
}

func TestAdminSpendRejectsNegativeChange(t *testing.T) {
	phoneRoutine, externalOwner, recovery, vaultCosigner, arkadeCosigner, phoneDirect := testKeys(t)
	op, err := NewOperational(OperationalKeys{PhoneRoutineBIP340: phoneRoutine.PubKey(), ExternalOwnerWallet: externalOwner.PubKey(), VaultCosignerBase: vaultCosigner.PubKey(), ArkadeCosignerBase: arkadeCosigner.PubKey(), PhoneDirectP256: phoneDirect})
	if err != nil {
		t.Fatal(err)
	}
	prevTx, opoint := fakeFund(t, op.PkScript, 10_000)
	dest, _ := txscript.PayToTaprootScript(recovery.PubKey())
	if _, err := AdminSpend(op, prevTx, opoint, dest, 20_000, 500, 0); err == nil {
		t.Fatal("overspend accepted")
	}
	if _, err := AdminSpend(op, prevTx, opoint, dest, 100, 500, 0); err == nil {
		t.Fatal("dust dest accepted")
	}
	if _, err := AdminSpend(nil, prevTx, opoint, dest, 5_000, 500, 0); err == nil {
		t.Fatal("nil vault accepted")
	}
	wrongHash := opoint
	wrongHash.Hash = chainhash.Hash{1}
	if _, err := AdminSpend(op, prevTx, wrongHash, dest, 5_000, 500, 0); err == nil {
		t.Fatal("hash mismatch accepted")
	}
}

func fakeFund(t *testing.T, pk []byte, value int64) (*wire.MsgTx, wire.OutPoint) {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{}})
	tx.AddTxOut(&wire.TxOut{Value: value, PkScript: pk})
	h := tx.TxHash()
	return tx, wire.OutPoint{Hash: h, Index: 0}
}
