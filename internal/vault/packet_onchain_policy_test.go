package vault_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/application"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// TestArkadePacketOnchainPolicy measures the finalized routine spend
// that carries only a direct transaction-bound P-256 signature in the Arkade
// OP_RETURN packet, then offers it to a live regtest node when reachable.
//
// The packet is part of the Bitcoin transaction. Pre-v30 Core (and many
// Knots/custom policies) will not relay a scriptPubKey larger than 83 bytes.
// Core 30 defaults to 100_000 and typically will.
func TestArkadePacketOnchainPolicy(t *testing.T) {
	_, evidence, sizes := buildFinalizedCollaborative(t, nil)

	if sizes.PacketScriptBytes <= fixture.PreCore30DatacarrierBytes {
		t.Fatalf("packet scriptPubKey is %d bytes; expected to exceed the pre-Core-30 %d-byte datacarrier default",
			sizes.PacketScriptBytes, fixture.PreCore30DatacarrierBytes)
	}
	if sizes.PacketScriptBytes > fixture.Core30DatacarrierBytes {
		t.Fatalf("packet scriptPubKey is %d bytes; exceeds the Core 30 default datacarrier of %d",
			sizes.PacketScriptBytes, fixture.Core30DatacarrierBytes)
	}
	if len(evidence.DirectSig) != 64 {
		t.Fatalf("direct signature length = %d, want 64", len(evidence.DirectSig))
	}
	if !bytes.Contains(sizes.PacketPayload, evidence.DirectSig) {
		t.Fatal("packet payload does not contain the one-item direct signature")
	}
	if sizes.TxVBytes <= 0 || sizes.TxSerializeBytes <= sizes.PacketScriptBytes {
		t.Fatalf("implausible whole-transaction size: %+v", sizes)
	}

	t.Logf("arkade packet scriptPubKey=%dB payload=%dB  tx=%dB stripped=%dB vsize=%dvB",
		sizes.PacketScriptBytes, len(sizes.PacketPayload),
		sizes.TxSerializeBytes, sizes.TxStrippedBytes, sizes.TxVBytes)
	t.Logf("pre-v30 default datacarrier=%dB  Core30 default=%dB  packet exceeds pre-v30 by %dB",
		fixture.PreCore30DatacarrierBytes, fixture.Core30DatacarrierBytes,
		sizes.PacketScriptBytes-fixture.PreCore30DatacarrierBytes)

	t.Run("regtest_node_policy", func(t *testing.T) {
		if !nigiriAvailable(t) {
			t.Skip("nigiri RPC not reachable; start the regtest stack to broadcast against real node policy")
		}
		broadcastAgainstRegtest(t, sizes)
	})
}

type onchainSizes struct {
	PacketScriptBytes int
	PacketPayload     []byte
	TxSerializeBytes  int
	TxStrippedBytes   int
	TxVBytes          int
}

type directAuthorizationEvidence struct {
	DirectSig []byte
}

func buildFinalizedCollaborative(t *testing.T, prev *wire.MsgTx) (*wire.MsgTx, directAuthorizationEvidence, onchainSizes) {
	t.Helper()
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	providerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	directP256, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	webauthnP256, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(webauthn.CompressedP256(directP256), webauthn.CompressedP256(webauthnP256)) {
		t.Fatal("test setup failed: WebAuthn and DirectP256 keys are not distinct")
	}
	op, err := vault.NewOperational(vault.OperationalKeys{
		PhoneRoutineBIP340:  hot.PubKey(),
		PhoneDirectP256:     webauthn.CompressedP256(directP256),
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerBase:   providerKey.PubKey(),
		ArkadeCosignerBase:  arkadeKey.PubKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := txscript.PayToTaprootScript(recipient.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	if prev == nil {
		prev = wire.NewMsgTx(2)
		prev.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Index: math.MaxUint32},
			Sequence:         wire.MaxTxInSequenceNum,
		})
		prev.AddTxOut(&wire.TxOut{Value: 200_000, PkScript: op.PkScript})
	}

	var vout uint32
	found := false
	for i, out := range prev.TxOut {
		if bytes.Equal(out.PkScript, op.PkScript) {
			vout = uint32(i)
			found = true
			break
		}
	}
	if !found {
		t.Fatal("prevout is not the operational vault")
	}

	spend, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault:           op,
		PrevTx:          prev,
		PrevOutPoint:    wire.OutPoint{Hash: prev.TxHash(), Index: vout},
		RecipientScript: dest,
		RecipientAmount: 40_000,
		Fee:             1_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	directSig := signPacketP256LowS(t, directP256, spend.Challenge)
	if err := vault.SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		t.Fatal(err)
	}

	hotSig, err := vault.SignLeaf(spend.Packet.UnsignedTx, spend.Prevout, op.Leaves.Routine.Script, hot)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(spend.Packet, hot.PubKey(), op.Leaves.Routine.Hash, hotSig)
	if _, err := (application.LocalSigner{Priv: providerKey}).Sign(context.Background(), spend.Packet); err != nil {
		t.Fatal(err)
	}
	if _, err := (application.LocalSigner{Priv: arkadeKey}).Sign(context.Background(), spend.Packet); err != nil {
		t.Fatal(err)
	}
	if err := vault.FinalizeRoutine(spend.Packet, op); err != nil {
		t.Fatal(err)
	}
	final, err := extractFinalized(spend.Packet)
	if err != nil {
		t.Fatal(err)
	}
	sizes, err := measureOnchain(final)
	if err != nil {
		t.Fatal(err)
	}
	return final, directAuthorizationEvidence{DirectSig: directSig}, sizes
}

func signPacketP256LowS(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("direct P-256 digest length = %d, want 32", len(digest))
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(half) > 0 {
		s.Sub(n, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func extractFinalized(ptx *psbt.Packet) (*wire.MsgTx, error) {
	if ptx == nil || ptx.UnsignedTx == nil || len(ptx.Inputs) != 1 {
		return nil, fmt.Errorf("finalized collaborative psbt")
	}
	if len(ptx.Inputs[0].FinalScriptWitness) == 0 {
		return nil, fmt.Errorf("missing final script witness")
	}
	wit, err := txutils.ReadTxWitness(ptx.Inputs[0].FinalScriptWitness)
	if err != nil {
		return nil, err
	}
	tx := ptx.UnsignedTx.Copy()
	tx.TxIn[0].Witness = wit
	return tx, nil
}

func measureOnchain(tx *wire.MsgTx) (onchainSizes, error) {
	var packet *wire.TxOut
	for _, out := range tx.TxOut {
		if extension.IsExtension(out.PkScript) {
			if packet != nil {
				return onchainSizes{}, fmt.Errorf("multiple extension outputs")
			}
			packet = out
		}
	}
	if packet == nil {
		return onchainSizes{}, fmt.Errorf("missing arkade packet output")
	}
	if packet.Value != 0 {
		return onchainSizes{}, fmt.Errorf("packet output must be zero value")
	}
	entries, err := arkade.FindEmulatorPacket(tx)
	if err != nil {
		return onchainSizes{}, err
	}
	if len(entries) != 1 {
		return onchainSizes{}, fmt.Errorf("expected one emulator entry")
	}
	payload, err := extensionPayload(packet.PkScript)
	if err != nil {
		return onchainSizes{}, err
	}
	stripped := tx.SerializeSizeStripped()
	full := tx.SerializeSize()
	return onchainSizes{
		PacketScriptBytes: len(packet.PkScript),
		PacketPayload:     payload,
		TxSerializeBytes:  full,
		TxStrippedBytes:   stripped,
		TxVBytes:          (stripped*3 + full + 3) / 4,
	}, nil
}

func extensionPayload(script []byte) ([]byte, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_RETURN {
		return nil, fmt.Errorf("expected OP_RETURN")
	}
	if !tokenizer.Next() {
		return nil, fmt.Errorf("expected data push")
	}
	return append([]byte(nil), tokenizer.Data()...), nil
}

func nigiriAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("nigiri"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nigiri", "rpc", "getblockchaininfo")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func nigiriRPC(t *testing.T, args ...string) string {
	t.Helper()
	return execNigiri(t, append([]string{"rpc"}, args...)...)
}

type mempoolAccept struct {
	Txid         string `json:"txid"`
	Allowed      bool   `json:"allowed"`
	RejectReason string `json:"reject-reason"`
}

func broadcastAgainstRegtest(t *testing.T, measured onchainSizes) {
	t.Helper()
	t.Logf("regtest getnetworkinfo: %s", compactJSON(nigiriRPC(t, "getnetworkinfo")))

	// Rebuild against a faucet-funded prevout so the node evaluates
	// standardness, not just missing-inputs.
	hot, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	externalOwner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	providerKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	arkadeKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p256, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	op, err := vault.NewOperational(vault.OperationalKeys{
		PhoneRoutineBIP340:  hot.PubKey(),
		PhoneDirectP256:     webauthn.CompressedP256(p256),
		ExternalOwnerWallet: externalOwner.PubKey(),
		VaultCosignerBase:   providerKey.PubKey(),
		ArkadeCosignerBase:  arkadeKey.PubKey(),
	})
	if err != nil {
		t.Fatal(err)
	}

	fund := execNigiri(t, "faucet", op.Address, "0.01")
	txid := strings.TrimSpace(strings.TrimPrefix(fund, "txId:"))
	if txid == "" {
		// nigiri faucet sometimes prints just the txid.
		txid = firstField(fund)
	}
	time.Sleep(500 * time.Millisecond)
	rawHex := nigiriRPC(t, "getrawtransaction", txid)
	raw, err := hex.DecodeString(strings.TrimSpace(rawHex))
	if err != nil {
		t.Fatalf("funding tx hex: %v", err)
	}
	prev := wire.NewMsgTx(2)
	if err := prev.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}

	recipient, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := txscript.PayToTaprootScript(recipient.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	var vout uint32
	var inValue int64
	found := false
	for i, out := range prev.TxOut {
		if bytes.Equal(out.PkScript, op.PkScript) {
			vout = uint32(i)
			inValue = out.Value
			found = true
			break
		}
	}
	if !found {
		t.Fatal("faucet did not pay the operational address")
	}
	fee := int64(1_000)
	recipientAmt := int64(40_000)
	if inValue <= recipientAmt+fee+fixture.DustSats {
		t.Fatalf("faucet output %d too small", inValue)
	}

	spend, err := vault.BuildRoutineSpend(vault.SpendParams{
		Vault:           op,
		PrevTx:          prev,
		PrevOutPoint:    wire.OutPoint{Hash: prev.TxHash(), Index: vout},
		RecipientScript: dest,
		RecipientAmount: recipientAmt,
		Fee:             fee,
	})
	if err != nil {
		t.Fatal(err)
	}
	directSig := signPacketP256LowS(t, p256, spend.Challenge)
	if err := vault.SetPacketWitness(spend.Packet.UnsignedTx, wire.TxWitness{directSig}); err != nil {
		t.Fatal(err)
	}
	hotSig, err := vault.SignLeaf(spend.Packet.UnsignedTx, spend.Prevout, op.Leaves.Routine.Script, hot)
	if err != nil {
		t.Fatal(err)
	}
	vault.AddPartialSig(spend.Packet, hot.PubKey(), op.Leaves.Routine.Hash, hotSig)
	if _, err := (application.LocalSigner{Priv: providerKey}).Sign(context.Background(), spend.Packet); err != nil {
		t.Fatal(err)
	}
	if err := vault.FinalizeRoutine(spend.Packet, op); err != nil {
		t.Fatal(err)
	}
	final, err := extractFinalized(spend.Packet)
	if err != nil {
		t.Fatal(err)
	}
	live, err := measureOnchain(final)
	if err != nil {
		t.Fatal(err)
	}
	if live.PacketScriptBytes != measured.PacketScriptBytes {
		t.Logf("live packet scriptPubKey=%dB (synthetic fixture was %dB)", live.PacketScriptBytes, measured.PacketScriptBytes)
	}

	var buf bytes.Buffer
	if err := final.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	hexTx := hex.EncodeToString(buf.Bytes())
	acceptRaw := nigiriRPC(t, "testmempoolaccept", `["`+hexTx+`"]`)
	t.Logf("testmempoolaccept: %s", compactJSON(acceptRaw))

	var accepted []mempoolAccept
	if err := json.Unmarshal([]byte(acceptRaw), &accepted); err != nil {
		t.Fatalf("decode testmempoolaccept: %v\n%s", err, acceptRaw)
	}
	if len(accepted) != 1 {
		t.Fatalf("testmempoolaccept returned %d results", len(accepted))
	}
	result := accepted[0]
	switch {
	case result.Allowed:
		sent := nigiriRPC(t, "sendrawtransaction", hexTx)
		t.Logf("sendrawtransaction %s", strings.TrimSpace(sent))
	case isDatacarrierReject(result.RejectReason):
		t.Logf("regtest node rejected the packet under its datacarrier policy (%s); Core 30 defaults usually accept this, older/custom policies do not", result.RejectReason)
	default:
		t.Fatalf("regtest node rejected the routine spend: %s", result.RejectReason)
	}
}

func execNigiri(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nigiri", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nigiri %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func isDatacarrierReject(reason string) bool {
	r := strings.ToLower(reason)
	return strings.Contains(r, "datacarrier") || strings.Contains(r, "scriptpubkey")
}

func firstField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	return fields[len(fields)-1]
}

func compactJSON(s string) string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	out, err := json.Marshal(v)
	if err != nil {
		return s
	}
	return string(out)
}
