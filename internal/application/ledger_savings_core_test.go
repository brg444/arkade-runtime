package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// Opt-in, disposable regtest only. Joins authenticated enrollment and durable
// Guardian authorization to funded Bitcoin Core acceptance of the exact bytes.
func TestLedgerSavingsFundedServiceCore(t *testing.T) {
	container := os.Getenv("VAULT_LEDGER_TEST_CORE_CONTAINER")
	if container == "" {
		t.Skip("set VAULT_LEDGER_TEST_CORE_CONTAINER to an isolated regtest container")
	}
	rpc := func(wallet string, args ...string) string {
		t.Helper()
		command := []string{"exec", container, "bitcoin-cli", "-regtest", "-rpcuser=native-fixture", "-rpcpassword=disposable-local-test"}
		if wallet != "" {
			command = append(command, "-rpcwallet="+wallet)
		}
		output, err := exec.Command("docker", append(command, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture RPC %s: %v: %s", args[0], err, output)
		}
		return strings.TrimSpace(string(output))
	}
	var network struct {
		NetworkActive bool `json:"networkactive"`
		Connections   int  `json:"connections"`
	}
	if err := json.Unmarshal([]byte(rpc("", "getnetworkinfo")), &network); err != nil {
		t.Fatal(err)
	}
	if network.NetworkActive || network.Connections != 0 {
		t.Fatal("regtest must have networking disabled")
	}
	var chain struct {
		Chain string `json:"chain"`
	}
	if err := json.Unmarshal([]byte(rpc("", "getblockchaininfo")), &chain); err != nil {
		t.Fatal(err)
	}
	if chain.Chain != "regtest" {
		t.Fatal("refusing non-regtest chain")
	}
	wallet := "ledger-service-" + strings.ReplaceAll(t.TempDir(), "/", "-")
	rpc("", "createwallet", wallet)
	t.Cleanup(func() { rpc("", "unloadwallet", wallet) })
	miner := rpc(wallet, "getnewaddress")
	rpc(wallet, "generatetoaddress", "101", miner)
	for _, advanced := range []bool{false, true} {
		roles := []string{"hardware", "phone"}
		if advanced {
			roles = append(roles, "recovery")
		}
		for _, role := range roles {
			for change := uint32(0); change < 2; change++ {
				f := ledgerEnrollmentReady(t, advanced)
				f.finish(t)
				request := f.signer.request(t, "initiate", role, "", change)
				packet, err := parsePSBT(request.retainedPSBT)
				if err != nil {
					t.Fatal(err)
				}
				address, err := btcutil.NewAddressTaproot(packet.Inputs[0].WitnessUtxo.PkScript[2:], &chaincfg.RegressionNetParams)
				if err != nil {
					t.Fatal(err)
				}
				parentID := rpc(wallet, "sendtoaddress", address.EncodeAddress(), "0.001")
				rpc(wallet, "generatetoaddress", "1", miner)
				parentBytes, err := hex.DecodeString(rpc("", "getrawtransaction", parentID))
				if err != nil {
					t.Fatal(err)
				}
				parent := wire.NewMsgTx(2)
				if err := parent.Deserialize(bytes.NewReader(parentBytes)); err != nil {
					t.Fatal(err)
				}
				index := -1
				for i, out := range parent.TxOut {
					if out.Value == 100000 && bytes.Equal(out.PkScript, packet.Inputs[0].WitnessUtxo.PkScript) {
						index = i
					}
				}
				if index < 0 {
					t.Fatal("funded Savings output missing")
				}
				packet.UnsignedTx.TxIn[0].PreviousOutPoint = wire.OutPoint{Hash: parent.TxHash(), Index: uint32(index)}
				packet.Inputs[0].NonWitnessUtxo = parent
				packet.Inputs[0].WitnessUtxo = parent.TxOut[index]
				f.signer.approve(t, &request, packet)
				req := TransitionRequest{VaultID: f.start.VaultID, Purpose: "initiate", PSBT: request.retainedPSBT, LedgerSavings: &LedgerSavingsTransitionRequest{Claimant: role, Change: &change}}
				if role == "phone" {
					digest, err := LedgerSavingsTransitionDigest(request.keyContext, "initiate", role, "", change, packet.UnsignedTx, packet.Inputs[0].WitnessUtxo)
					if err != nil {
						t.Fatal(err)
					}
					req.PhoneAuthorization = &LedgerSavingsPhoneAuthorization{Digest: hex.EncodeToString(digest), Signature: hex.EncodeToString(request.directProof)}
					req.SessionAssertionRequest = f.assertion(t, passkeyPurposeTransition)
				}
				signed, err := f.svc.SignTransition(t.Context(), req)
				if err != nil {
					t.Fatal(err)
				}
				f.restart(t)
				if role == "phone" {
					req.SessionAssertionRequest = f.assertion(t, passkeyPurposeTransition)
				}
				replay, err := f.svc.SignTransition(t.Context(), req)
				if err != nil || !replay.Replay || replay.SignedPSBT != signed.SignedPSBT {
					t.Fatalf("restart changed authorized bytes: %v", err)
				}
				approved, err := parsePSBT(signed.SignedPSBT)
				if err != nil {
					t.Fatal(err)
				}
				if len(approved.Inputs[0].TaprootScriptSpendSig) != 2 {
					t.Fatal("expected user and Guardian signatures")
				}
				leaf := approved.Inputs[0].TaprootLeafScript[0]
				tx := approved.UnsignedTx.Copy()
				tx.TxIn[0].Witness = wire.TxWitness{approved.Inputs[0].TaprootScriptSpendSig[1].Signature, approved.Inputs[0].TaprootScriptSpendSig[0].Signature, leaf.Script, leaf.ControlBlock}
				var raw bytes.Buffer
				if err := tx.Serialize(&raw); err != nil {
					t.Fatal(err)
				}
				txhex := hex.EncodeToString(raw.Bytes())
				argument, _ := json.Marshal([]string{txhex})
				var acceptance []struct {
					Allowed bool   `json:"allowed"`
					Reject  string `json:"reject-reason"`
				}
				if err := json.Unmarshal([]byte(rpc("", "testmempoolaccept", string(argument))), &acceptance); err != nil {
					t.Fatal(err)
				}
				if len(acceptance) != 1 || !acceptance[0].Allowed {
					t.Fatalf("Core rejected service recovery advanced=%v claimant=%s change=%d: %+v", advanced, role, change, acceptance)
				}
				if got := rpc("", "sendrawtransaction", txhex); got != tx.TxHash().String() {
					t.Fatal("Core returned different txid")
				}
				rpc(wallet, "generatetoaddress", "1", miner)
			}
		}
	}
}
