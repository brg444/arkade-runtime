package policy

import (
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
