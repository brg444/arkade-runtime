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
	if action, err := DecideReplay(pending, *pending); err != nil || action != ReplayResign {
		t.Fatalf("exact unsigned retry: %v %v", action, err)
	}
	different := *pending
	different.LastSighash = "22"
	if _, err := DecideReplay(pending, different); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("different unsigned operation was not held: %v", err)
	}
	different.Signature = []byte("different-signed-psbt")
	if _, err := DecideReplay(pending, different); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("different signed operation was not held: %v", err)
	}
}

func TestApplyRecoveryReplayAllowsExactUnsignedRetry(t *testing.T) {
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
	action, stored, err = led.ApplyRecoveryReplay(next)
	if err != nil || action != ReplayResign || stored == nil || len(stored.Signature) != 0 {
		t.Fatalf("exact unsigned retry: %v %v stored=%+v", action, err, stored)
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

func TestRecoveryReplacementDoesNotCarryPreviousSignature(t *testing.T) {
	led := openPolicyTestLedger(t, nil)
	createPolicyTestVault(t, led, "vault-a", 0x72)
	first := RecoverySession{
		VaultID: "vault-a", Purpose: sessionPurposeInitiate,
		InputTxid: "aa11", InputVout: 0, DestScript: "5120ab",
		LastSighash: "11", Signature: []byte("original-signed-psbt"),
	}
	if _, _, err := led.ApplyRecoveryReplay(first); err != nil {
		t.Fatal(err)
	}
	replacement := first
	replacement.LastSighash = "22"
	replacement.Signature = nil
	for i := 0; i < 2; i++ {
		action, stored, err := led.ApplyRecoveryReplay(replacement)
		if err != nil || action != ReplayResign || stored == nil || len(stored.Signature) != 0 || stored.LastSighash != "22" {
			t.Fatalf("replacement attempt %d: action=%s stored=%+v err=%v", i, action, stored, err)
		}
	}
	// A late response from the old signer cannot overwrite a pending replacement.
	if _, _, err := led.ApplyRecoveryReplay(first); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("old signed candidate overwrote pending replacement: %v", err)
	}
	replacement.Signature = []byte("replacement-signed-psbt")
	if _, _, err := led.ApplyRecoveryReplay(replacement); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.ApplyRecoveryReplay(first); !errors.Is(err, ErrRecoveryBusy) {
		t.Fatalf("old signing completion overwrote the signed replacement: %v", err)
	}
	replacement.Signature = nil
	action, stored, err := led.ApplyRecoveryReplay(replacement)
	if err != nil || action != ReplayReplay || stored == nil || string(stored.Signature) != "replacement-signed-psbt" {
		t.Fatalf("lost-response replay: action=%s stored=%+v err=%v", action, stored, err)
	}
}
