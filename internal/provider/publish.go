package provider

import (
	"bytes"
	"context"
	"fmt"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/vault"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// Broadcaster is the narrow node surface used after local verification.
type Broadcaster interface {
	Broadcast(ctx context.Context, rawTx []byte) (txid string, err error)
	Lookup(ctx context.Context, txid string) (confirmations int64, found bool, err error)
}

// PublishResult is the on-chain view of one completed issuance.
type PublishResult struct {
	Txid            string `json:"txid"`
	Confirmations   int64  `json:"confirmations"`
	PeriodSpent     int64  `json:"periodSpent"`
	PeriodRemaining int64  `json:"periodRemaining"`
}

// Publish takes only the Arkade challenge. It loads the ledger's completed
// signed PSBT, never a client PSBT or raw transaction, then verifies and
// broadcasts that exact spend.
func (s *Service) Publish(ctx context.Context, challengeHex string) (*PublishResult, error) {
	return s.PublishVault(ctx, "", challengeHex)
}

func (s *Service) PublishVault(ctx context.Context, vaultID, challengeHex string) (*PublishResult, error) {
	if err := s.attachLedgerIntegrity(); err != nil {
		return nil, err
	}
	raw, txid, err := s.preparePublication(ctx, vaultID, challengeHex)
	if err != nil {
		return nil, err
	}
	return s.dispatchPublication(ctx, vaultID, raw, txid)
}

// PublicationStatus takes only the completed issuance challenge, rederives
// the canonical txid from the stored PSBT, and looks that txid up. An
// arbitrary txid is never accepted.
func (s *Service) PublicationStatus(ctx context.Context, challengeHex string) (*PublishResult, error) {
	return s.PublicationStatusVault(ctx, "", challengeHex)
}

func (s *Service) PublicationStatusVault(ctx context.Context, vaultID, challengeHex string) (*PublishResult, error) {
	if err := s.attachLedgerIntegrity(); err != nil {
		return nil, err
	}
	_, txid, err := s.preparePublication(ctx, vaultID, challengeHex)
	if err != nil {
		return nil, err
	}
	if s.Broadcaster == nil {
		return nil, fmt.Errorf("publisher not configured")
	}
	conf, found, err := s.Broadcaster.Lookup(ctx, txid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("unpublished")
	}
	return s.publishResult(ctx, vaultID, txid, conf)
}

func (s *Service) preparePublication(ctx context.Context, vaultID, challengeHex string) ([]byte, string, error) {
	id, snap, err := s.resolveSpendVault(vaultID)
	if err != nil {
		return nil, "", err
	}
	op := snap.Operational
	digest, err := decodeHex(challengeHex)
	if err != nil || len(digest) != 32 {
		return nil, "", fmt.Errorf("challenge")
	}
	if s.Ledger == nil {
		return nil, "", fmt.Errorf("unknown or incomplete challenge")
	}
	stored, ok, err := s.Ledger.Completed(ctx, id, digest)
	if err != nil {
		return nil, "", err
	}
	if !ok || stored == "" {
		return nil, "", fmt.Errorf("unknown or incomplete challenge")
	}
	ptx, _, err := parseAndVerifyPrevout(stored)
	if err != nil {
		return nil, "", fmt.Errorf("stored psbt: %w", err)
	}
	if _, err := classifySpend(ptx, op); err != nil {
		return nil, "", err
	}
	got, err := vault.Challenge(ptx, op)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(got, digest) {
		return nil, "", fmt.Errorf("recomputed challenge does not match")
	}
	if err := verifyStoredDirectWitness(ptx, op, digest); err != nil {
		return nil, "", err
	}
	if len(ptx.Inputs[0].FinalScriptWitness) != 0 || len(ptx.Inputs[0].FinalScriptSig) != 0 {
		return nil, "", fmt.Errorf("preexisting final script")
	}
	clone, err := clonePacket(ptx)
	if err != nil {
		return nil, "", err
	}
	if err := vault.FinalizeRoutine(clone, op); err != nil {
		return nil, "", err
	}
	if err := vault.ExecuteFinalizedRoutine(clone, op); err != nil {
		return nil, "", fmt.Errorf("local script engine: %w", err)
	}
	tx, err := vault.ExtractFinalizedTx(clone)
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), tx.TxHash().String(), nil
}

func verifyStoredDirectWitness(ptx *psbt.Packet, op *vault.Built, challenge []byte) error {
	cred, err := ptxDirectPub(op)
	if err != nil {
		return err
	}
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return err
	}
	if len(packet) != 1 {
		return fmt.Errorf("emulator packet")
	}
	if len(packet[0].Witness) != 1 || len(packet[0].Witness[0]) != 64 {
		return fmt.Errorf("packet witness must be the one-item 64-byte direct signature")
	}
	return verifyDirectAuth(cred, challenge, packet[0].Witness[0])
}

func ptxDirectPub(op *vault.Built) ([]byte, error) {
	if op == nil || len(op.Record.PhoneDirectP256) == 0 {
		return nil, fmt.Errorf("direct p256 required")
	}
	return op.Record.PhoneDirectP256, nil
}

func (s *Service) dispatchPublication(ctx context.Context, vaultID string, raw []byte, txid string) (*PublishResult, error) {
	if s.Broadcaster == nil {
		return nil, fmt.Errorf("publisher not configured")
	}
	if txid == "" {
		return nil, fmt.Errorf("txid required")
	}
	if conf, found, err := s.Broadcaster.Lookup(ctx, txid); err != nil {
		return nil, err
	} else if found {
		return s.publishResult(ctx, vaultID, txid, conf)
	}
	got, err := s.Broadcaster.Broadcast(ctx, raw)
	if err != nil {
		conf, found, lookErr := s.Broadcaster.Lookup(ctx, txid)
		if lookErr != nil {
			return nil, lookErr
		}
		if found {
			return s.publishResult(ctx, vaultID, txid, conf)
		}
		return nil, err
	}
	if got == "" {
		return nil, fmt.Errorf("empty returned txid")
	}
	if got != txid {
		return nil, fmt.Errorf("returned txid mismatch")
	}
	conf, found, lookErr := s.Broadcaster.Lookup(ctx, txid)
	if lookErr != nil {
		return nil, lookErr
	}
	if !found {
		return nil, fmt.Errorf("unpublished")
	}
	return s.publishResult(ctx, vaultID, txid, conf)
}

func (s *Service) publishResult(ctx context.Context, vaultID, txid string, conf int64) (*PublishResult, error) {
	id, err := s.routeVaultID(vaultID)
	if err != nil {
		return nil, err
	}
	st, err := s.statusFor(ctx, id)
	if err != nil {
		return nil, err
	}
	return &PublishResult{
		Txid:            txid,
		Confirmations:   conf,
		PeriodSpent:     st.PeriodSpent,
		PeriodRemaining: st.PeriodRemaining,
	}, nil
}

// NodeBroadcaster adapts Bitcoin RPC to Broadcaster. Mempool-already-there
// is treated as a successful idempotent publish.
type NodeBroadcaster struct {
	Chain Chain
}

func (n *NodeBroadcaster) Broadcast(ctx context.Context, rawTx []byte) (string, error) {
	if n == nil || n.Chain == nil {
		return "", fmt.Errorf("publisher not configured")
	}
	ok, reason, err := n.Chain.TestMempoolAccept(ctx, rawTx)
	if err != nil {
		return "", err
	}
	txid, decErr := rawTxid(rawTx)
	if !ok {
		if alreadyPublished(reason) && decErr == nil {
			return txid, nil
		}
		return "", fmt.Errorf("mempool rejected: %s", reason)
	}
	sent, err := n.Chain.SendRawTransaction(ctx, rawTx)
	if err != nil {
		return "", err
	}
	if sent == "" {
		return "", fmt.Errorf("empty returned txid")
	}
	return sent, nil
}

func (n *NodeBroadcaster) Lookup(ctx context.Context, txid string) (int64, bool, error) {
	if n == nil || n.Chain == nil {
		return 0, false, fmt.Errorf("publisher not configured")
	}
	return n.Chain.LookupTx(ctx, txid)
}

func alreadyPublished(reason string) bool {
	r := fmt.Sprintf("%s", reason)
	return containsAny(r, "txn-already-in-mempool", "txn-already-known", "already in block")
}

func containsAny(s string, parts ...string) bool {
	low := bytes.ToLower([]byte(s))
	for _, p := range parts {
		if bytes.Contains(low, bytes.ToLower([]byte(p))) {
			return true
		}
	}
	return false
}

func rawTxid(raw []byte) (string, error) {
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		return "", err
	}
	return tx.TxHash().String(), nil
}
