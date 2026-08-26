package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

const (
	vaultBoardV2ChainTimeout       = 12 * time.Second
	vaultBoardV2ChainTxLimit       = 512 * 1024
	vaultBoardV2ChainBlockLimit    = 32 * 1024
	vaultBoardV2ChainOutspendLimit = 32 * 1024
	vaultBoardV2ChainTextLimit     = 256
)

type vaultBoardV2ConfirmedOutpoint struct {
	Txid               []byte
	Vout               uint32
	ValueSats          int64
	PkScript           []byte
	SequenceAnchorMTP  int64
	TipMTP             int64
	Spent              bool
	SpendingTxid       string
	FundingBlockHash   string
	FundingBlockHeight int64
}

type vaultBoardV2Chain interface {
	confirmedOutpoint(context.Context, string, uint32) (vaultBoardV2ConfirmedOutpoint, error)
	revalidateOutpoint(context.Context, vaultBoardV2ConfirmedOutpoint) (vaultBoardV2ConfirmedOutpoint, error)
}

type esploraVaultBoardV2Chain struct {
	origin string
	hc     httpDoer
}

func dialVaultBoardV2Chain() (vaultBoardV2Chain, error) {
	return dialVaultBoardV2ChainWithClient(deployment.MutinynetEsploraOrigin, &http.Client{
		Timeout: vaultBoardV2ChainTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("vault-board-v2 Esplora redirects are disabled")
		},
	})
}

func dialVaultBoardV2ChainWithClient(rawOrigin string, hc httpDoer) (vaultBoardV2Chain, error) {
	base := strings.TrimSuffix(rawOrigin, "/api")
	origin, err := canonicalHTTPSOrigin(base)
	if err != nil || rawOrigin != origin+"/api" || rawOrigin != deployment.MutinynetEsploraOrigin {
		return nil, fmt.Errorf("vault-board-v2 Esplora origin must be the release pin")
	}
	if hc == nil {
		return nil, fmt.Errorf("vault-board-v2 Esplora HTTP client required")
	}
	return &esploraVaultBoardV2Chain{origin: rawOrigin, hc: hc}, nil
}

type vaultBoardV2EsploraTx struct {
	Txid string `json:"txid"`
	Vout []struct {
		Value        int64  `json:"value"`
		ScriptPubkey string `json:"scriptpubkey"`
	} `json:"vout"`
	Status vaultBoardV2EsploraStatus `json:"status"`
}

type vaultBoardV2EsploraStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHeight int64  `json:"block_height"`
	BlockHash   string `json:"block_hash"`
}

type vaultBoardV2EsploraBlock struct {
	ID         string `json:"id"`
	Height     int64  `json:"height"`
	MedianTime int64  `json:"mediantime"`
}

type vaultBoardV2EsploraOutspend struct {
	Spent bool   `json:"spent"`
	Txid  string `json:"txid"`
	Vin   int64  `json:"vin"`
}

func (e *esploraVaultBoardV2Chain) confirmedOutpoint(ctx context.Context, txid string, vout uint32) (vaultBoardV2ConfirmedOutpoint, error) {
	if e == nil || e.hc == nil || e.origin != deployment.MutinynetEsploraOrigin || requireTxid(txid) != nil {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 release-pinned chain query required")
	}
	var funding vaultBoardV2EsploraTx
	if err := e.getJSON(ctx, "/tx/"+txid, vaultBoardV2ChainTxLimit, &funding); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardV2FundingTx(funding, txid, vout); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}

	var fundingBlock vaultBoardV2EsploraBlock
	if err := e.getJSON(ctx, "/block/"+funding.Status.BlockHash, vaultBoardV2ChainBlockLimit, &fundingBlock); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardV2Block(fundingBlock, funding.Status.BlockHash, funding.Status.BlockHeight); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 funding block: %w", err)
	}
	if funding.Status.BlockHeight <= 0 {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 funding predecessor unavailable")
	}
	predecessorHash, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(funding.Status.BlockHeight-1, 10), vaultBoardV2ChainTextLimit)
	if err != nil || requireTxid(predecessorHash) != nil {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 funding predecessor")
	}
	var predecessor vaultBoardV2EsploraBlock
	if err := e.getJSON(ctx, "/block/"+predecessorHash, vaultBoardV2ChainBlockLimit, &predecessor); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardV2Block(predecessor, predecessorHash, funding.Status.BlockHeight-1); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 funding predecessor: %w", err)
	}

	tipHash, err := e.getText(ctx, "/blocks/tip/hash", vaultBoardV2ChainTextLimit)
	if err != nil || requireTxid(tipHash) != nil {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 chain tip")
	}
	var tip vaultBoardV2EsploraBlock
	if err := e.getJSON(ctx, "/block/"+tipHash, vaultBoardV2ChainBlockLimit, &tip); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardV2Block(tip, tipHash, tip.Height); err != nil || tip.Height < fundingBlock.Height || tip.MedianTime < predecessor.MedianTime {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 chain tip does not contain funding block")
	}

	var outspend vaultBoardV2EsploraOutspend
	if err := e.getJSON(ctx, "/tx/"+txid+"/outspend/"+strconv.FormatUint(uint64(vout), 10), vaultBoardV2ChainOutspendLimit, &outspend); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if outspend.Spent {
		if requireTxid(outspend.Txid) != nil || outspend.Vin < 0 {
			return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 invalid outspend")
		}
	} else if outspend.Txid != "" || outspend.Vin != 0 {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 contradictory outspend")
	}

	// Re-read the funding status after the dependent block queries. A reorg or
	// status mutation between reads is ambiguous and must not authorize signing.
	var confirm vaultBoardV2EsploraTx
	if err := e.getJSON(ctx, "/tx/"+txid, vaultBoardV2ChainTxLimit, &confirm); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardV2FundingTx(confirm, txid, vout); err != nil ||
		confirm.Status != funding.Status || confirm.Vout[vout].Value != funding.Vout[vout].Value ||
		confirm.Vout[vout].ScriptPubkey != funding.Vout[vout].ScriptPubkey {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 funding confirmation changed during query")
	}
	canonicalFundingHash, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(funding.Status.BlockHeight, 10), vaultBoardV2ChainTextLimit)
	if err != nil || canonicalFundingHash != funding.Status.BlockHash {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 funding block is not canonical")
	}
	var confirmOutspend vaultBoardV2EsploraOutspend
	if err := e.getJSON(ctx, "/tx/"+txid+"/outspend/"+strconv.FormatUint(uint64(vout), 10), vaultBoardV2ChainOutspendLimit, &confirmOutspend); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if confirmOutspend != outspend {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 outspend changed during query")
	}
	script, _ := hex.DecodeString(funding.Vout[vout].ScriptPubkey)
	display, _ := hex.DecodeString(txid)
	return vaultBoardV2ConfirmedOutpoint{
		Txid: display, Vout: vout, ValueSats: funding.Vout[vout].Value, PkScript: script,
		SequenceAnchorMTP: predecessor.MedianTime, TipMTP: tip.MedianTime,
		Spent: outspend.Spent, SpendingTxid: outspend.Txid,
		FundingBlockHash: funding.Status.BlockHash, FundingBlockHeight: funding.Status.BlockHeight,
	}, nil
}

func (e *esploraVaultBoardV2Chain) revalidateOutpoint(ctx context.Context, prior vaultBoardV2ConfirmedOutpoint) (vaultBoardV2ConfirmedOutpoint, error) {
	txid := hex.EncodeToString(prior.Txid)
	if e == nil || e.hc == nil || e.origin != deployment.MutinynetEsploraOrigin || requireTxid(txid) != nil ||
		requireTxid(prior.FundingBlockHash) != nil || prior.FundingBlockHeight <= 0 {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 release-pinned chain revalidation required")
	}
	canonical, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(prior.FundingBlockHeight, 10), vaultBoardV2ChainTextLimit)
	if err != nil || canonical != prior.FundingBlockHash {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 funding block is no longer canonical")
	}
	tipHash, err := e.getText(ctx, "/blocks/tip/hash", vaultBoardV2ChainTextLimit)
	if err != nil || requireTxid(tipHash) != nil {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 chain tip")
	}
	var tip vaultBoardV2EsploraBlock
	if err := e.getJSON(ctx, "/block/"+tipHash, vaultBoardV2ChainBlockLimit, &tip); err != nil ||
		validateVaultBoardV2Block(tip, tipHash, tip.Height) != nil || tip.Height < prior.FundingBlockHeight || tip.MedianTime < prior.SequenceAnchorMTP {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 chain tip does not contain funding block")
	}
	var outspend vaultBoardV2EsploraOutspend
	if err := e.getJSON(ctx, "/tx/"+txid+"/outspend/"+strconv.FormatUint(uint64(prior.Vout), 10), vaultBoardV2ChainOutspendLimit, &outspend); err != nil {
		return vaultBoardV2ConfirmedOutpoint{}, err
	}
	if outspend.Spent {
		if requireTxid(outspend.Txid) != nil || outspend.Vin < 0 {
			return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 invalid outspend")
		}
	} else if outspend.Txid != "" || outspend.Vin != 0 {
		return vaultBoardV2ConfirmedOutpoint{}, fmt.Errorf("vault-board-v2 contradictory outspend")
	}
	current := prior
	current.TipMTP = tip.MedianTime
	current.Spent = outspend.Spent
	current.SpendingTxid = outspend.Txid
	return current, nil
}

func validateVaultBoardV2FundingTx(tx vaultBoardV2EsploraTx, txid string, vout uint32) error {
	if tx.Txid != txid || !tx.Status.Confirmed || requireTxid(tx.Status.BlockHash) != nil ||
		tx.Status.BlockHeight < 0 || uint64(vout) >= uint64(len(tx.Vout)) {
		return fmt.Errorf("vault-board-v2 confirmed funding transaction required")
	}
	output := tx.Vout[vout]
	if output.Value <= 0 || len(output.ScriptPubkey) == 0 || output.ScriptPubkey != strings.ToLower(output.ScriptPubkey) {
		return fmt.Errorf("vault-board-v2 funding output")
	}
	script, err := hex.DecodeString(output.ScriptPubkey)
	if err != nil || len(script) == 0 || hex.EncodeToString(script) != output.ScriptPubkey {
		return fmt.Errorf("vault-board-v2 funding output")
	}
	return nil
}

func validateVaultBoardV2Block(block vaultBoardV2EsploraBlock, hash string, height int64) error {
	if block.ID != hash || requireTxid(block.ID) != nil || block.Height != height || block.Height < 0 || block.MedianTime <= 0 {
		return fmt.Errorf("block identity")
	}
	return nil
}

func (e *esploraVaultBoardV2Chain) getJSON(ctx context.Context, path string, limit int64, dest any) error {
	res, err := e.get(ctx, path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := requireVaultBoardV2ContentType(res, "application/json"); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		zeroServiceBytes(raw)
		return fmt.Errorf("vault-board-v2 Esplora response exceeds limit")
	}
	defer zeroServiceBytes(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("vault-board-v2 Esplora JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("vault-board-v2 Esplora trailing JSON")
	}
	return nil
}

func (e *esploraVaultBoardV2Chain) getText(ctx context.Context, path string, limit int64) (string, error) {
	res, err := e.get(ctx, path)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if err := requireVaultBoardV2ContentType(res, "text/plain"); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		zeroServiceBytes(raw)
		return "", fmt.Errorf("vault-board-v2 Esplora response exceeds limit")
	}
	defer zeroServiceBytes(raw)
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("vault-board-v2 Esplora canonical text")
	}
	return value, nil
}

func (e *esploraVaultBoardV2Chain) get(ctx context.Context, path string) (*http.Response, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "?") || strings.Contains(path, "#") {
		return nil, fmt.Errorf("vault-board-v2 Esplora path")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.origin+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	res, err := e.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v2 Esplora unavailable: %w", err)
	}
	if res == nil || res.Body == nil {
		return nil, fmt.Errorf("vault-board-v2 Esplora empty response")
	}
	if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4*1024))
		return nil, fmt.Errorf("vault-board-v2 Esplora HTTP %d", res.StatusCode)
	}
	return res, nil
}

func requireVaultBoardV2ContentType(res *http.Response, want string) error {
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != want {
		return fmt.Errorf("vault-board-v2 Esplora content type")
	}
	return nil
}

var _ vaultBoardV2Chain = (*esploraVaultBoardV2Chain)(nil)
