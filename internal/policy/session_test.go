package policy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestDecideRecoveryReplay(t *testing.T) {
	next := RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "AA11", InputVout: 0, DestScript: "5120ab",
	}
	action, err := DecideReplay(nil, next)
	if err != nil || action != ReplaySign {
		t.Fatalf("first sign: %v %v", action, err)
	}
	existing := &RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 0, DestScript: "5120ab",
		LastSighash: "11", Signature: []byte{1},
	}
	next.InputTxid = "aa11"
	next.LastSighash = "11"
	action, err = DecideReplay(existing, next)
	if err != nil || action != ReplayReplay {
		t.Fatalf("same sighash: %v %v", action, err)
	}
	next.LastSighash = "22"
	action, err = DecideReplay(existing, next)
	if err != nil || action != ReplayResign {
		t.Fatalf("fee bump: %v %v", action, err)
	}
	next.DestScript = "5120cd"
	if _, err := DecideReplay(existing, next); err == nil {
		t.Fatal("second destination accepted")
	}
	pending := &RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 0, DestScript: "5120ab", LastSighash: "11",
	}
	if _, err := DecideReplay(pending, *pending); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("unsigned operation was not held: %v", err)
	}
}

func TestApplyRecoveryReplayRefusesSecondUnsignedWorker(t *testing.T) {
	led := openPolicyTestLedger(t, nil)
	createPolicyTestVault(t, led, "vault-a", 0x71)
	next := RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 0, DestScript: "5120ab", LastSighash: "11",
	}
	action, stored, err := led.ApplyRecoveryReplay(next)
	if err != nil || action != ReplaySign || stored == nil {
		t.Fatalf("first: %v %v", action, err)
	}
	if _, _, err := led.ApplyRecoveryReplay(next); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("second unsigned worker: %v", err)
	}
	next.Signature = []byte("signed-psbt")
	action, stored, err = led.ApplyRecoveryReplay(next)
	if err != nil || action != ReplayResign || stored == nil || !bytes.Equal(stored.Signature, next.Signature) {
		t.Fatalf("finalize: %v %v stored=%+v", action, err, stored)
	}
}

func TestRecoverySessionMACCoversSignatureAndSighash(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, sha256.Size)
	rec := RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", DestScript: "5120ab",
		LastSighash: "11", Signature: []byte{1, 2, 3},
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:01Z",
	}
	if err := sealSession(&rec, key); err != nil {
		t.Fatal(err)
	}
	mac := append([]byte(nil), rec.IntegrityMAC...)
	rec.Signature = []byte{9, 9, 9}
	rec.IntegrityMAC = mac
	if err := verifySession(&rec, key); err == nil {
		t.Fatal("tampered signature verified")
	}
	rec.Signature = []byte{1, 2, 3}
	rec.LastSighash = "22"
	rec.IntegrityMAC = mac
	if err := verifySession(&rec, key); err == nil {
		t.Fatal("tampered sighash verified")
	}
}
