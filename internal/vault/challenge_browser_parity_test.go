package vault

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

// This is the same fixed PSBT consumed by web/psbtcheck.test.js. Locking the
// vector on both sides prevents the browser's independent implementation from
// silently drifting away from the Go policy boundary.
func TestBrowserArkadeChallengeParityVector(t *testing.T) {
	const encoded = "cHNidP8BAJQCAAAAAczO3m1HhVAfqCP4aql3Ep4l0y41m1hhI1T2GvyTx9kbAAAAAAD/////AyBOAAAAAAAAFgAUqqqqqqqqqqqqqqqqqqqqqqqqqqp8DwEAAAAAACJRIHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYAAAAAAAAAAAOagxBUksBBwEAAAKquwAAAAAAAAEBK5BfAQAAAAAAIlEgeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5gBAwQAAAAAIhXAeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5gCUcAAAAAA"
	const want = "58a500edd00d9a7c371c280ab2c59b938ad9d15f9905f77831f1feee8fd10b94"

	packet, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
	if err != nil {
		t.Fatalf("decode parity PSBT: %v", err)
	}
	if len(packet.Inputs) != 1 || len(packet.Inputs[0].TaprootLeafScript) != 1 {
		t.Fatal("parity PSBT does not contain one tap leaf")
	}
	built := &Built{Leaves: Leaves{Routine: &Leaf{
		Script: packet.Inputs[0].TaprootLeafScript[0].Script,
	}}}
	digest, err := Challenge(packet, built)
	if err != nil {
		t.Fatalf("Go Arkade challenge: %v", err)
	}
	if got := hex.EncodeToString(digest); got != want {
		t.Fatalf("Go Arkade challenge = %s, browser vector wants %s", got, want)
	}
}
