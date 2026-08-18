package policy

import "testing"

func TestDecideReplaySignOnceDest(t *testing.T) {
	next := RecoverySession{
		VaultID:    "vault-a",
		Purpose:    sessionPurposeInitiate,
		InputTxid:  "AA" + "11",
		InputVout:  0,
		DestScript: "5120ab",
	}
	action, err := DecideReplay(nil, next)
	if err != nil || action != ReplaySign {
		t.Fatalf("first sign: %v %v", action, err)
	}
	existing := &RecoverySession{
		VaultID:     "vault-a",
		Purpose:     sessionPurposeInitiate,
		InputTxid:   "aa11",
		InputVout:   0,
		DestScript:  "5120ab",
		LastSighash: "11",
		Signature:   []byte{1},
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
		t.Fatal("second dest accepted")
	}
	if _, err := DecideReplay(existing, RecoverySession{VaultID: "vault-a", Purpose: "claim", InputTxid: "aa11", DestScript: "5120ab"}); err == nil {
		t.Fatal("claim purpose accepted")
	}
}
