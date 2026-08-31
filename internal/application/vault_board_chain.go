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
	vaultBoardChainTimeout       = 12 * time.Second
	vaultBoardChainTxLimit       = 512 * 1024
	vaultBoardChainBlockLimit    = 32 * 1024
	vaultBoardChainOutspendLimit = 32 * 1024
	vaultBoardChainTextLimit     = 256
)

type vaultBoardConfirmedOutpoint struct {
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

type vaultBoardChain interface {
	confirmedOutpoint(context.Context, string, uint32) (vaultBoardConfirmedOutpoint, error)
	revalidateOutpoint(context.Context, vaultBoardConfirmedOutpoint) (vaultBoardConfirmedOutpoint, error)
}

type esploraVaultBoardChain struct {
	origin string
	hc     httpDoer
}

func dialVaultBoardChain() (vaultBoardChain, error) {
	return dialVaultBoardChainWithClient(deployment.MutinynetEsploraOrigin, &http.Client{
		Timeout: vaultBoardChainTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("vault-board-v1 Esplora redirects are disabled")
		},
	})
}

func dialVaultBoardChainWithClient(rawOrigin string, hc httpDoer) (vaultBoardChain, error) {
	base := strings.TrimSuffix(rawOrigin, "/api")
	origin, err := canonicalHTTPSOrigin(base)
	if err != nil || rawOrigin != origin+"/api" || rawOrigin != deployment.MutinynetEsploraOrigin {
		return nil, fmt.Errorf("vault-board-v1 Esplora origin must be the release pin")
	}
	if hc == nil {
		return nil, fmt.Errorf("vault-board-v1 Esplora HTTP client required")
	}
	return &esploraVaultBoardChain{origin: rawOrigin, hc: hc}, nil
}

type vaultBoardEsploraTx struct {
	Txid string `json:"txid"`
	Vout []struct {
		Value        int64  `json:"value"`
		ScriptPubkey string `json:"scriptpubkey"`
	} `json:"vout"`
	Status vaultBoardEsploraStatus `json:"status"`
}

type vaultBoardEsploraStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHeight int64  `json:"block_height"`
	BlockHash   string `json:"block_hash"`
}

type vaultBoardEsploraBlock struct {
	ID         string `json:"id"`
	Height     int64  `json:"height"`
	MedianTime int64  `json:"mediantime"`
}

type vaultBoardEsploraOutspend struct {
	Spent bool   `json:"spent"`
	Txid  string `json:"txid"`
	Vin   int64  `json:"vin"`
}

func (e *esploraVaultBoardChain) confirmedOutpoint(ctx context.Context, txid string, vout uint32) (vaultBoardConfirmedOutpoint, error) {
	if e == nil || e.hc == nil || e.origin != deployment.MutinynetEsploraOrigin || requireTxid(txid) != nil {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 release-pinned chain query required")
	}
	var funding vaultBoardEsploraTx
	if err := e.getJSON(ctx, "/tx/"+txid, vaultBoardChainTxLimit, &funding); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardFundingTx(funding, txid, vout); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}

	var fundingBlock vaultBoardEsploraBlock
	if err := e.getJSON(ctx, "/block/"+funding.Status.BlockHash, vaultBoardChainBlockLimit, &fundingBlock); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardBlock(fundingBlock, funding.Status.BlockHash, funding.Status.BlockHeight); err != nil {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 funding block: %w", err)
	}
	if funding.Status.BlockHeight <= 0 {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 funding predecessor unavailable")
	}
	predecessorHash, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(funding.Status.BlockHeight-1, 10), vaultBoardChainTextLimit)
	if err != nil || requireTxid(predecessorHash) != nil {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 funding predecessor")
	}
	var predecessor vaultBoardEsploraBlock
	if err := e.getJSON(ctx, "/block/"+predecessorHash, vaultBoardChainBlockLimit, &predecessor); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardBlock(predecessor, predecessorHash, funding.Status.BlockHeight-1); err != nil {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 funding predecessor: %w", err)
	}

	tipHash, err := e.getText(ctx, "/blocks/tip/hash", vaultBoardChainTextLimit)
	if err != nil || requireTxid(tipHash) != nil {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 chain tip")
	}
	var tip vaultBoardEsploraBlock
	if err := e.getJSON(ctx, "/block/"+tipHash, vaultBoardChainBlockLimit, &tip); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardBlock(tip, tipHash, tip.Height); err != nil || tip.Height < fundingBlock.Height || tip.MedianTime < predecessor.MedianTime {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 chain tip does not contain funding block")
	}

	var outspend vaultBoardEsploraOutspend
	if err := e.getJSON(ctx, "/tx/"+txid+"/outspend/"+strconv.FormatUint(uint64(vout), 10), vaultBoardChainOutspendLimit, &outspend); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if outspend.Spent {
		if requireTxid(outspend.Txid) != nil || outspend.Vin < 0 {
			return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 invalid outspend")
		}
	} else if outspend.Txid != "" || outspend.Vin != 0 {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 contradictory outspend")
	}

	// Re-read the funding status after the dependent block queries. A reorg or
	// status mutation between reads is ambiguous and must not authorize signing.
	var confirm vaultBoardEsploraTx
	if err := e.getJSON(ctx, "/tx/"+txid, vaultBoardChainTxLimit, &confirm); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if err := validateVaultBoardFundingTx(confirm, txid, vout); err != nil ||
		confirm.Status != funding.Status || confirm.Vout[vout].Value != funding.Vout[vout].Value ||
		confirm.Vout[vout].ScriptPubkey != funding.Vout[vout].ScriptPubkey {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 funding confirmation changed during query")
	}
	canonicalFundingHash, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(funding.Status.BlockHeight, 10), vaultBoardChainTextLimit)
	if err != nil || canonicalFundingHash != funding.Status.BlockHash {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 funding block is not canonical")
	}
	var confirmOutspend vaultBoardEsploraOutspend
	if err := e.getJSON(ctx, "/tx/"+txid+"/outspend/"+strconv.FormatUint(uint64(vout), 10), vaultBoardChainOutspendLimit, &confirmOutspend); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if confirmOutspend != outspend {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 outspend changed during query")
	}
	script, _ := hex.DecodeString(funding.Vout[vout].ScriptPubkey)
	display, _ := hex.DecodeString(txid)
	return vaultBoardConfirmedOutpoint{
		Txid: display, Vout: vout, ValueSats: funding.Vout[vout].Value, PkScript: script,
		SequenceAnchorMTP: predecessor.MedianTime, TipMTP: tip.MedianTime,
		Spent: outspend.Spent, SpendingTxid: outspend.Txid,
		FundingBlockHash: funding.Status.BlockHash, FundingBlockHeight: funding.Status.BlockHeight,
	}, nil
}

func (e *esploraVaultBoardChain) revalidateOutpoint(ctx context.Context, prior vaultBoardConfirmedOutpoint) (vaultBoardConfirmedOutpoint, error) {
	txid := hex.EncodeToString(prior.Txid)
	if e == nil || e.hc == nil || e.origin != deployment.MutinynetEsploraOrigin || requireTxid(txid) != nil ||
		requireTxid(prior.FundingBlockHash) != nil || prior.FundingBlockHeight <= 0 {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 release-pinned chain revalidation required")
	}
	canonical, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(prior.FundingBlockHeight, 10), vaultBoardChainTextLimit)
	if err != nil || canonical != prior.FundingBlockHash {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 funding block is no longer canonical")
	}
	tipHash, err := e.getText(ctx, "/blocks/tip/hash", vaultBoardChainTextLimit)
	if err != nil || requireTxid(tipHash) != nil {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 chain tip")
	}
	var tip vaultBoardEsploraBlock
	if err := e.getJSON(ctx, "/block/"+tipHash, vaultBoardChainBlockLimit, &tip); err != nil ||
		validateVaultBoardBlock(tip, tipHash, tip.Height) != nil || tip.Height < prior.FundingBlockHeight || tip.MedianTime < prior.SequenceAnchorMTP {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 chain tip does not contain funding block")
	}
	var outspend vaultBoardEsploraOutspend
	if err := e.getJSON(ctx, "/tx/"+txid+"/outspend/"+strconv.FormatUint(uint64(prior.Vout), 10), vaultBoardChainOutspendLimit, &outspend); err != nil {
		return vaultBoardConfirmedOutpoint{}, err
	}
	if outspend.Spent {
		if requireTxid(outspend.Txid) != nil || outspend.Vin < 0 {
			return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 invalid outspend")
		}
	} else if outspend.Txid != "" || outspend.Vin != 0 {
		return vaultBoardConfirmedOutpoint{}, fmt.Errorf("vault-board-v1 contradictory outspend")
	}
	current := prior
	current.TipMTP = tip.MedianTime
	current.Spent = outspend.Spent
	current.SpendingTxid = outspend.Txid
	return current, nil
}

func validateVaultBoardFundingTx(tx vaultBoardEsploraTx, txid string, vout uint32) error {
	if tx.Txid != txid || !tx.Status.Confirmed || requireTxid(tx.Status.BlockHash) != nil ||
		tx.Status.BlockHeight < 0 || uint64(vout) >= uint64(len(tx.Vout)) {
		return fmt.Errorf("vault-board-v1 confirmed funding transaction required")
	}
	output := tx.Vout[vout]
	if output.Value <= 0 || len(output.ScriptPubkey) == 0 || output.ScriptPubkey != strings.ToLower(output.ScriptPubkey) {
		return fmt.Errorf("vault-board-v1 funding output")
	}
	script, err := hex.DecodeString(output.ScriptPubkey)
	if err != nil || len(script) == 0 || hex.EncodeToString(script) != output.ScriptPubkey {
		return fmt.Errorf("vault-board-v1 funding output")
	}
	return nil
}

func validateVaultBoardBlock(block vaultBoardEsploraBlock, hash string, height int64) error {
	if block.ID != hash || requireTxid(block.ID) != nil || block.Height != height || block.Height < 0 || block.MedianTime <= 0 {
		return fmt.Errorf("block identity")
	}
	return nil
}

func (e *esploraVaultBoardChain) getJSON(ctx context.Context, path string, limit int64, dest any) error {
	res, err := e.get(ctx, path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := requireVaultBoardContentType(res, "application/json"); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		zeroServiceBytes(raw)
		return fmt.Errorf("vault-board-v1 Esplora response exceeds limit")
	}
	defer zeroServiceBytes(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("vault-board-v1 Esplora JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("vault-board-v1 Esplora trailing JSON")
	}
	return nil
}

func (e *esploraVaultBoardChain) getText(ctx context.Context, path string, limit int64) (string, error) {
	res, err := e.get(ctx, path)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	mediaType, _, contentTypeErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
	// The release-pinned Mutinynet gateway serves its block-height hash
	// endpoint as text/html even though the body is the canonical bare hash.
	// Permit that one observed representation only; every returned value is
	// still length-bounded and then validated as an exact txid by the caller.
	blockHeightHTML := strings.HasPrefix(path, "/block-height/") && mediaType == "text/html"
	if contentTypeErr != nil || (mediaType != "text/plain" && !blockHeightHTML) {
		return "", fmt.Errorf("vault-board-v1 Esplora content type")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		zeroServiceBytes(raw)
		return "", fmt.Errorf("vault-board-v1 Esplora response exceeds limit")
	}
	defer zeroServiceBytes(raw)
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("vault-board-v1 Esplora canonical text")
	}
	return value, nil
}

func (e *esploraVaultBoardChain) get(ctx context.Context, path string) (*http.Response, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "?") || strings.Contains(path, "#") {
		return nil, fmt.Errorf("vault-board-v1 Esplora path")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.origin+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	res, err := e.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault-board-v1 Esplora unavailable: %w", err)
	}
	if res == nil || res.Body == nil {
		return nil, fmt.Errorf("vault-board-v1 Esplora empty response")
	}
	if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4*1024))
		return nil, fmt.Errorf("vault-board-v1 Esplora HTTP %d", res.StatusCode)
	}
	return res, nil
}

func requireVaultBoardContentType(res *http.Response, want string) error {
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != want {
		return fmt.Errorf("vault-board-v1 Esplora content type")
	}
	return nil
}

var _ vaultBoardChain = (*esploraVaultBoardChain)(nil)
