package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func TestConnectorDualGuardianAcceptsWalletCandidates(t *testing.T) {
	var vectors []struct {
		Contract struct{ Network, ConnectorType, ProtectionTier, PhonePub, VaultCosignerBase, ArkadeCosignerBase string }
		Control  string
		Rules    struct {
			ConnectorScript                                     string
			WitnessBytes, AbsoluteFeeCapSats, FeerateCapSatPerV int64
		}
		Payments []struct{ PhonePSBT string }
	}
	raw, err := os.ReadFile("../../experiments/connector/testdata/dual-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 8 {
		t.Fatal("network/kind/tier matrix incomplete")
	}
	decode := func(s string) []byte {
		t.Helper()
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	key := func(s string) *btcec.PublicKey {
		t.Helper()
		p, e := btcec.ParsePubKey(decode(s))
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	for _, v := range vectors {
		t.Run(v.Contract.Network+"/"+v.Contract.ConnectorType+"/"+v.Contract.ProtectionTier, func(t *testing.T) {
			rules := connector.Rules{Version: 2, ConnectorScript: decode(v.Rules.ConnectorScript), WitnessBytes: v.Rules.WitnessBytes, AbsoluteFeeCapSats: v.Rules.AbsoluteFeeCapSats, FeerateCapSatPerV: v.Rules.FeerateCapSatPerV}
			auth, err := newConnectorGuardianAuthorization(key(v.Contract.PhonePub), key(v.Contract.VaultCosignerBase), key(v.Contract.ArkadeCosignerBase), decode(v.Control), rules.ConnectorScript, rules)
			if err != nil {
				t.Fatal(err)
			}
			if len(v.Payments) != 2 {
				t.Fatal("full/partial matrix incomplete")
			}
			for _, payment := range v.Payments {
				p, err := psbt.NewFromRawBytes(bytes.NewReader(decode(payment.PhonePSBT)), false)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = validateConnectorGuardianCandidate(encodeConnectorStage(t, p), auth); err != nil {
					t.Fatal("wallet candidate rejected", err)
				}
			}
		})
	}
}
