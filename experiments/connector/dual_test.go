package connector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
	candidate "github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// These fixtures are produced independently by the wallet with public test keys.
func TestDualWalletVectors(t *testing.T) {
	var vectors []struct {
		Contract struct {
			VaultID, Network, TemplateVersion, ConnectorType, PhonePub, HardwarePub, PhoneDirectP256, VaultCosignerBase, ArkadeCosignerBase, RecoveryPub, ProtectionTier string
			SpendingPolicy                                                                                                                                               program.SpendingPolicy
		}
		Origin struct {
			PublicKey   string
			Fingerprint uint32
			Path        []uint32
		}
		Program, SavingsScript, Leaf, Control, EnrollmentDigest string
		Rules                                                   struct {
			ConnectorScript                                     string
			WitnessBytes, AbsoluteFeeCapSats, FeerateCapSatPerV int64
		}
		Payments []struct {
			Full                     bool
			PhonePSBT, FinalTx, Txid string
		}
	}
	raw, err := os.ReadFile("testdata/dual-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 8 {
		t.Fatal("expected complete network/type/tier matrix")
	}
	for _, v := range vectors {
		t.Run(v.Contract.Network+"/"+v.Contract.ConnectorType+"/"+v.Contract.ProtectionTier, func(t *testing.T) {
			decode := func(s string) []byte {
				t.Helper()
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			pub := func(s string) *btcec.PublicKey {
				t.Helper()
				if s == "" {
					return nil
				}
				p, e := btcec.ParsePubKey(decode(s))
				if e != nil {
					t.Fatal(e)
				}
				return p
			}
			in := savings.FamilyInput{
				VaultID: v.Contract.VaultID, Network: v.Contract.Network, Phone: pub(v.Contract.PhonePub), Hardware: pub(v.Contract.HardwarePub), Recovery: pub(v.Contract.RecoveryPub),
				PhoneDirectP256: decode(v.Contract.PhoneDirectP256), VaultCosignerBase: pub(v.Contract.VaultCosignerBase), ArkadeCosignerBase: pub(v.Contract.ArkadeCosignerBase),
				TemplateVersion: v.Contract.TemplateVersion, ServerFreeClawback: true, ProtectionTier: v.Contract.ProtectionTier, SpendingPolicy: v.Contract.SpendingPolicy,
			}
			kind := candidate.Kind(v.Contract.ConnectorType)
			fam, err := candidate.BuildFamily(in, kind)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fam.Recovery.Savings.PkScript, decode(v.SavingsScript)) {
				t.Fatalf("wallet/Guardian Savings script differs: Go %x, wallet %s", fam.Recovery.Savings.PkScript, v.SavingsScript)
			}
			net := &chaincfg.MainNetParams
			if v.Contract.Network == "mutinynet" {
				net = &chaincfg.SigNetParams
			}
			addr, err := btcutil.NewAddressTaproot(decode(v.SavingsScript)[2:], net)
			if err != nil {
				t.Fatal(err)
			}
			if fam.Recovery.Savings.Address != addr.EncodeAddress() {
				t.Fatalf("wallet/Guardian Savings address differs: Go %s, wallet %s", fam.Recovery.Savings.Address, addr.EncodeAddress())
			}
			if !bytes.Equal(fam.Leaf, decode(v.Leaf)) {
				t.Fatalf("wallet/Guardian leaf differs: Go %x, wallet %s", fam.Leaf, v.Leaf)
			}
			if !bytes.Equal(fam.Control, decode(v.Control)) {
				t.Fatalf("wallet/Guardian control differs: Go %x, wallet %s", fam.Control, v.Control)
			}
			digest, err := candidate.EnrollmentDigest(in, candidate.KeyOrigin{Type: kind, PublicKey: decode(v.Origin.PublicKey), Fingerprint: v.Origin.Fingerprint, Path: append([]uint32(nil), v.Origin.Path...)})
			if err != nil {
				t.Fatal(err)
			}
			if digest != v.EnrollmentDigest {
				t.Fatalf("wallet/Guardian enrollment digest differs: Go %s, wallet %s", digest, v.EnrollmentDigest)
			}
			rules := candidate.Rules{Version: 2, ConnectorScript: decode(v.Rules.ConnectorScript), WitnessBytes: v.Rules.WitnessBytes, AbsoluteFeeCapSats: v.Rules.AbsoluteFeeCapSats, FeerateCapSatPerV: v.Rules.FeerateCapSatPerV}
			policy, err := candidate.BuildProgram(rules)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(policy, decode(v.Program)) {
				t.Fatalf("wallet/Guardian program differs: Go %d bytes, wallet %d bytes\nGo: %x\nwallet: %s", len(policy), len(decode(v.Program)), policy, v.Program)
			}
			for _, payment := range v.Payments {
				p, err := psbt.NewFromRawBytes(bytes.NewReader(decode(payment.PhonePSBT)), false)
				if err != nil {
					t.Fatal(err)
				}
				parents := candidate.Parents{}
				for i, in := range p.UnsignedTx.TxIn {
					parents[in.PreviousOutPoint] = p.Inputs[i].NonWitnessUtxo
				}
				if err := candidate.Validate(rules, p.UnsignedTx, parents); err != nil {
					t.Fatalf("wallet candidate full=%v: %v", payment.Full, err)
				}
				final := wire.NewMsgTx(2)
				if err := final.Deserialize(bytes.NewReader(decode(payment.FinalTx))); err != nil {
					t.Fatal(err)
				}
				if final.TxHash().String() != payment.Txid {
					t.Fatal("transaction identity mismatch")
				}
				for i, in := range final.TxIn {
					prev := parents.FetchPrevOutput(in.PreviousOutPoint)
					vm, err := txscript.NewEngine(prev.PkScript, final, i, txscript.StandardVerifyFlags, nil, txscript.NewTxSigHashes(final, parents), prev.Value, parents)
					if err == nil {
						err = vm.Execute()
					}
					if err != nil {
						t.Fatalf("Bitcoin input %d: %v", i, err)
					}
				}
				for _, attack := range []string{"recipient", "reserve", "packet", "extra-output"} {
					bad := p.UnsignedTx.Copy()
					switch attack {
					case "recipient":
						bad.TxOut[0].PkScript[3] ^= 1
					case "reserve":
						bad.TxOut[len(bad.TxOut)-4].Value--
					case "packet":
						bad.TxOut[len(bad.TxOut)-1].PkScript = append(bad.TxOut[len(bad.TxOut)-1].PkScript, 0)
					case "extra-output":
						bad.AddTxOut(wire.NewTxOut(0, []byte{0x6a}))
					}
					if err := candidate.Validate(rules, bad, parents); err == nil {
						t.Fatalf("accepted %s", attack)
					}
				}
			}
		})
	}
}
