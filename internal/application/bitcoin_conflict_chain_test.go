package application

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func conflictFixture(t *testing.T, commitment *wire.MsgTx) policy.BitcoinConflictEvidence {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&commitment.TxIn[0].PreviousOutPoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(123, []byte{0x51}))
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	prev := tx.TxIn[0].PreviousOutPoint
	return policy.BitcoinConflictEvidence{Kind: policy.BitcoinConflictKind, CommitmentTxid: commitment.TxHash().String(), FundingTxid: prev.Hash.String(), FundingVout: prev.Index, ConflictingTxid: tx.TxHash().String(), ConflictingVin: 0, BlockHash: strings.Repeat("ab", 32), BlockHeight: 100, TipHash: strings.Repeat("cd", 32), TipHeight: 105, RawTransaction: hex.EncodeToString(b.Bytes())}
}

func TestBitcoinConflictRequiresCanonicalDeepConflict(t *testing.T) {
	commitment := wire.NewMsgTx(2)
	commitment.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}, nil, nil))
	commitment.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	proof := conflictFixture(t, commitment)
	id, _ := deployment.IdentityFor("mainnet")
	for _, scenario := range []string{"valid", "unspent", "same transaction", "unconfirmed", "five confirmations", "wrong raw transaction", "wrong vin", "wrong checkpoint", "status race", "outspend race", "reorg", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			counts := map[string]int{}
			doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
				path := strings.TrimPrefix(req.URL.Path, "/api")
				counts[path]++
				if req.URL.Host != "mempool.space" || req.URL.Scheme != "https" || req.Method != "GET" {
					t.Fatalf("unpinned request: %s", req.URL)
				}
				switch path {
				case "/block-height/" + strconv.FormatInt(id.CheckpointHeight, 10):
					hash := id.CheckpointHash
					if scenario == "wrong checkpoint" {
						hash = proof.BlockHash
					}
					return vaultBoardTextResponse(200, hash), nil
				case "/tx/" + proof.FundingTxid + "/outspends":
					if scenario == "unavailable" {
						return nil, fmt.Errorf("offline")
					}
					if scenario == "unspent" || (scenario == "outspend race" && counts[path] > 1) {
						return jsonResponse(200, `[{"spent":false}]`), nil
					}
					txid, vin := proof.ConflictingTxid, 0
					if scenario == "same transaction" {
						txid = proof.CommitmentTxid
					}
					if scenario == "wrong vin" {
						vin = 1
					}
					return jsonResponse(200, fmt.Sprintf(`[{"spent":true,"txid":%q,"vin":%d}]`, txid, vin)), nil
				case "/tx/" + proof.ConflictingTxid + "/status":
					if scenario == "unconfirmed" || (scenario == "status race" && counts[path] > 1) {
						return jsonResponse(200, `{"confirmed":false}`), nil
					}
					return jsonResponse(200, fmt.Sprintf(`{"confirmed":true,"block_height":100,"block_hash":%q}`, proof.BlockHash)), nil
				case "/tx/" + proof.ConflictingTxid + "/hex":
					raw := proof.RawTransaction
					if scenario == "wrong raw transaction" {
						raw += "00"
					}
					return vaultBoardTextResponse(200, raw), nil
				case "/blocks/tip/hash":
					return vaultBoardTextResponse(200, proof.TipHash), nil
				case "/block/" + proof.TipHash:
					height := 105
					if scenario == "five confirmations" {
						height = 104
					}
					return jsonResponse(200, fmt.Sprintf(`{"id":%q,"height":%d,"mediantime":100000}`, proof.TipHash, height)), nil
				case "/block-height/105":
					return vaultBoardTextResponse(200, proof.TipHash), nil
				case "/block-height/100":
					hash := proof.BlockHash
					if scenario == "reorg" {
						hash = proof.TipHash
					}
					return vaultBoardTextResponse(200, hash), nil
				default:
					t.Fatalf("unexpected request %s", path)
					return nil, nil
				}
			})
			chain := &esploraVaultBoardChain{origin: id.EsploraOrigin, hc: doer}
			got, err := chain.confirmedBitcoinConflict(t.Context(), "mainnet", commitment)
			switch scenario {
			case "valid":
				if err != nil || got == nil || *got != proof {
					t.Fatalf("proof %+v: %v", got, err)
				}
			case "unspent", "same transaction", "unconfirmed", "five confirmations":
				if err != nil || got != nil {
					t.Fatalf("premature release %+v: %v", got, err)
				}
			default:
				if err == nil || got != nil {
					t.Fatalf("accepted %s: %+v %v", scenario, got, err)
				}
			}
		})
	}
}

func TestBitcoinConflictRawTransactionMustSpendExactCommitmentInput(t *testing.T) {
	commitment := wire.NewMsgTx(2)
	commitment.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{1}, Index: 2}, nil, nil))
	commitment.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	proof := conflictFixture(t, commitment)
	for _, scenario := range []string{"foreign input", "wrong funding index", "wrong commitment", "wrong txid", "same transaction", "trailing bytes"} {
		t.Run(scenario, func(t *testing.T) {
			p := proof
			candidate := commitment.Copy()
			switch scenario {
			case "foreign input":
				candidate.TxIn[0].PreviousOutPoint.Hash[0]++
				p.CommitmentTxid = candidate.TxHash().String()
			case "wrong funding index":
				p.FundingVout++
			case "wrong commitment":
				p.CommitmentTxid = strings.Repeat("ff", 32)
			case "wrong txid":
				p.ConflictingTxid = strings.Repeat("ff", 32)
			case "same transaction":
				candidate.TxOut[0].Value = 123
				p.CommitmentTxid = candidate.TxHash().String()
			case "trailing bytes":
				p.RawTransaction += "00"
			}
			if err := verifyBitcoinConflictTransaction(p, candidate); err == nil {
				t.Fatal("invalid conflict accepted")
			}
		})
	}
}
