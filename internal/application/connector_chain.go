package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/brg444/arkade-runtime/internal/apperr"
	"github.com/brg444/arkade-runtime/internal/deployment"
)

// connectorOutpointState is server-observed chain state for one connector
// parent. Funding confirmation is proven canonical; spend observation alone
// never authorizes anything.
type connectorOutpointState struct {
	ValueSats          int64
	PkScript           []byte
	Spent              bool
	SpendingTxid       string
	FundingBlockHash   string
	FundingBlockHeight int64
}

// connectorChainView is the narrow pinned-chain boundary for connector
// withdrawals and reconciliation. confirmedOutpoint proves canonical funding
// confirmation plus current spend status; confirmedTransaction proves canonical
// confirmation of a candidate or conflicting spender. Timeouts, 404s, and
// empty mempools are returned as errors and never as negative proof.
type connectorChainView interface {
	confirmedOutpoint(ctx context.Context, txid string, vout uint32) (connectorOutpointState, error)
	confirmedTransaction(ctx context.Context, txid string) (blockHash string, blockHeight int64, err error)
}

var errConnectorTransactionUnconfirmed = errors.New("connector transaction is unconfirmed")

const (
	connectorChainTimeout       = 12 * time.Second
	connectorChainTxLimit       = 512 * 1024
	connectorChainOutspendLimit = 32 * 1024
	connectorChainTextLimit     = 256
)

type esploraConnectorChain struct {
	origin string
	hc     httpDoer
}

func dialConnectorChain(network string) (connectorChainView, error) {
	id, err := deployment.IdentityFor(network)
	if err != nil {
		return nil, err
	}
	return dialConnectorChainWithClient(id.EsploraOrigin, &http.Client{
		Timeout: connectorChainTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("connector Esplora redirects are disabled")
		},
	})
}

func dialConnectorChainWithClient(esploraOrigin string, hc httpDoer) (connectorChainView, error) {
	id, err := identityForEsploraOrigin(esploraOrigin)
	if err != nil || id.EsploraOrigin != esploraOrigin {
		return nil, fmt.Errorf("connector Esplora origin must be the release pin")
	}
	origin, canonErr := CanonicalHTTPSOrigin(strings.TrimSuffix(esploraOrigin, "/api"))
	if canonErr != nil || esploraOrigin != origin+"/api" {
		return nil, fmt.Errorf("connector Esplora origin must be the release pin")
	}
	if hc == nil {
		return nil, fmt.Errorf("connector Esplora HTTP client required")
	}
	return &esploraConnectorChain{origin: esploraOrigin, hc: hc}, nil
}

type connectorEsploraTx struct {
	Txid string `json:"txid"`
	Vout []struct {
		Value        int64  `json:"value"`
		ScriptPubkey string `json:"scriptpubkey"`
	} `json:"vout"`
	Status connectorEsploraStatus `json:"status"`
}

type connectorEsploraStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHeight int64  `json:"block_height"`
	BlockHash   string `json:"block_hash"`
}

type connectorEsploraOutspend struct {
	Spent bool   `json:"spent"`
	Txid  string `json:"txid"`
	Vin   int64  `json:"vin"`
}

// An absent boolean is ambiguous, not proof of an unspent or unconfirmed state.
func (s *connectorEsploraStatus) UnmarshalJSON(raw []byte) error {
	type plain connectorEsploraStatus
	var decoded struct {
		*plain
		Confirmed *bool `json:"confirmed"`
	}
	decoded.plain = (*plain)(s)
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	if decoded.Confirmed == nil {
		return fmt.Errorf("connector confirmation status missing")
	}
	s.Confirmed = *decoded.Confirmed
	return nil
}

func (s *connectorEsploraOutspend) UnmarshalJSON(raw []byte) error {
	type plain connectorEsploraOutspend
	var decoded struct {
		*plain
		Spent *bool `json:"spent"`
	}
	decoded.plain = (*plain)(s)
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	if decoded.Spent == nil {
		return fmt.Errorf("connector outspend status missing")
	}
	s.Spent = *decoded.Spent
	return nil
}

func (e *esploraConnectorChain) confirmedOutpoint(ctx context.Context, txid string, vout uint32) (connectorOutpointState, error) {
	if e == nil || e.hc == nil || !pinnedEsploraOrigin(e.origin) || requireTxid(txid) != nil {
		return connectorOutpointState{}, fmt.Errorf("connector release-pinned chain query required")
	}
	funding, err := e.confirmedFundingTx(ctx, txid, vout)
	if err != nil {
		return connectorOutpointState{}, err
	}
	outspend, err := e.getOutspend(ctx, txid, vout)
	if err != nil {
		return connectorOutpointState{}, err
	}
	// Re-read funding status and outspend after the dependent queries. A reorg
	// or status mutation between reads is ambiguous and must not authorize.
	confirm, err := e.confirmedFundingTx(ctx, txid, vout)
	if err != nil {
		return connectorOutpointState{}, err
	}
	if confirm.Status != funding.Status || confirm.Vout[vout].Value != funding.Vout[vout].Value ||
		confirm.Vout[vout].ScriptPubkey != funding.Vout[vout].ScriptPubkey {
		return connectorOutpointState{}, fmt.Errorf("connector funding confirmation changed during query")
	}
	confirmOutspend, err := e.getOutspend(ctx, txid, vout)
	if err != nil {
		return connectorOutpointState{}, err
	}
	if confirmOutspend != outspend {
		return connectorOutpointState{}, fmt.Errorf("connector outspend changed during query")
	}
	script, _ := hex.DecodeString(funding.Vout[vout].ScriptPubkey)
	return connectorOutpointState{
		ValueSats: funding.Vout[vout].Value, PkScript: script,
		Spent: outspend.Spent, SpendingTxid: outspend.Txid,
		FundingBlockHash: funding.Status.BlockHash, FundingBlockHeight: funding.Status.BlockHeight,
	}, nil
}

// confirmedTransaction proves a candidate or conflicting spender is confirmed
// in the current canonical chain. The status is double-read and the inclusion
// block is checked against the canonical block hash at its height.
func (e *esploraConnectorChain) confirmedTransaction(ctx context.Context, txid string) (string, int64, error) {
	if e == nil || e.hc == nil || !pinnedEsploraOrigin(e.origin) || requireTxid(txid) != nil {
		return "", 0, fmt.Errorf("connector release-pinned chain query required")
	}
	status, err := e.confirmedTxStatus(ctx, txid)
	if errors.Is(err, errConnectorTransactionUnconfirmed) {
		// A successfully decoded transaction that is repeatedly unconfirmed
		// is positive reorg evidence. A timeout or 404 is never such proof.
		_, secondErr := e.confirmedTxStatus(ctx, txid)
		if errors.Is(secondErr, errConnectorTransactionUnconfirmed) {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("connector confirmation changed during query")
	}
	if err != nil {
		return "", 0, err
	}
	second, err := e.confirmedTxStatus(ctx, txid)
	if err != nil {
		return "", 0, err
	}
	if second != status {
		return "", 0, fmt.Errorf("connector transaction confirmation changed during query")
	}
	return status.BlockHash, status.BlockHeight, nil
}

func (e *esploraConnectorChain) confirmedTxStatus(ctx context.Context, txid string) (connectorEsploraStatus, error) {
	var tx struct {
		Txid   string                  `json:"txid"`
		Status *connectorEsploraStatus `json:"status"`
	}
	if err := e.getJSON(ctx, "/tx/"+txid, connectorChainTxLimit, &tx); err != nil {
		return connectorEsploraStatus{}, err
	}
	if tx.Status == nil {
		return connectorEsploraStatus{}, fmt.Errorf("connector transaction status missing")
	}
	if tx.Txid == txid && !tx.Status.Confirmed && tx.Status.BlockHash == "" && tx.Status.BlockHeight == 0 {
		return connectorEsploraStatus{}, errConnectorTransactionUnconfirmed
	}
	if tx.Txid != txid || !tx.Status.Confirmed || requireTxid(tx.Status.BlockHash) != nil || tx.Status.BlockHeight <= 0 {
		return connectorEsploraStatus{}, fmt.Errorf("connector transaction is not confirmed")
	}
	canonical, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(tx.Status.BlockHeight, 10), connectorChainTextLimit)
	if err != nil || canonical != tx.Status.BlockHash {
		return connectorEsploraStatus{}, fmt.Errorf("connector transaction block is not canonical")
	}
	return *tx.Status, nil
}

// confirmedFundingTx loads a transaction, requires confirmation, and proves
// the inclusion block is canonical. vout must exist; value/script validation
// stays with the caller.
func (e *esploraConnectorChain) confirmedFundingTx(ctx context.Context, txid string, vout uint32) (connectorEsploraTx, error) {
	var funding connectorEsploraTx
	if err := e.getJSON(ctx, "/tx/"+txid, connectorChainTxLimit, &funding); err != nil {
		return connectorEsploraTx{}, err
	}
	if funding.Txid != txid || !funding.Status.Confirmed || requireTxid(funding.Status.BlockHash) != nil ||
		funding.Status.BlockHeight <= 0 || uint64(vout) >= uint64(len(funding.Vout)) {
		return connectorEsploraTx{}, fmt.Errorf("connector confirmed funding transaction required")
	}
	output := funding.Vout[vout]
	if output.Value <= 0 || output.ScriptPubkey == "" || output.ScriptPubkey != strings.ToLower(output.ScriptPubkey) {
		return connectorEsploraTx{}, fmt.Errorf("connector funding output")
	}
	script, err := hex.DecodeString(output.ScriptPubkey)
	if err != nil || len(script) == 0 || hex.EncodeToString(script) != output.ScriptPubkey {
		return connectorEsploraTx{}, fmt.Errorf("connector funding output")
	}
	canonical, err := e.getText(ctx, "/block-height/"+strconv.FormatInt(funding.Status.BlockHeight, 10), connectorChainTextLimit)
	if err != nil || canonical != funding.Status.BlockHash {
		return connectorEsploraTx{}, fmt.Errorf("connector funding block is not canonical")
	}
	return funding, nil
}

func (e *esploraConnectorChain) getOutspend(ctx context.Context, txid string, vout uint32) (connectorEsploraOutspend, error) {
	var outspends []connectorEsploraOutspend
	if err := e.getJSON(ctx, "/tx/"+txid+"/outspends", connectorChainOutspendLimit, &outspends); err != nil {
		return connectorEsploraOutspend{}, err
	}
	if uint64(vout) >= uint64(len(outspends)) {
		return connectorEsploraOutspend{}, fmt.Errorf("connector outspend set does not contain output")
	}
	out := outspends[vout]
	if out.Spent {
		if requireTxid(out.Txid) != nil || out.Vin < 0 {
			return connectorEsploraOutspend{}, fmt.Errorf("connector invalid outspend")
		}
	} else if out.Txid != "" || out.Vin != 0 {
		return connectorEsploraOutspend{}, fmt.Errorf("connector contradictory outspend")
	}
	return out, nil
}

func (e *esploraConnectorChain) getJSON(ctx context.Context, path string, limit int64, dest any) error {
	res, err := e.get(ctx, path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return fmt.Errorf("connector Esplora content type")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		zeroServiceBytes(raw)
		return fmt.Errorf("connector Esplora response exceeds limit")
	}
	defer zeroServiceBytes(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("connector Esplora JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("connector Esplora trailing JSON")
	}
	return nil
}

func (e *esploraConnectorChain) getText(ctx context.Context, path string, limit int64) (string, error) {
	res, err := e.get(ctx, path)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	mediaType, _, contentTypeErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
	blockHeightHTML := strings.HasPrefix(path, "/block-height/") && mediaType == "text/html"
	if contentTypeErr != nil || (mediaType != "text/plain" && !blockHeightHTML) {
		return "", fmt.Errorf("connector Esplora content type")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		zeroServiceBytes(raw)
		return "", fmt.Errorf("connector Esplora response exceeds limit")
	}
	defer zeroServiceBytes(raw)
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("connector Esplora canonical text")
	}
	return value, nil
}

func (e *esploraConnectorChain) get(ctx context.Context, path string) (*http.Response, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "?") || strings.Contains(path, "#") {
		return nil, fmt.Errorf("connector Esplora path")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.origin+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	res, err := e.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connector Esplora unavailable: %w", err)
	}
	if res == nil || res.Body == nil {
		return nil, fmt.Errorf("connector Esplora empty response")
	}
	if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4*1024))
		if res.StatusCode == http.StatusNotFound {
			return nil, apperr.New(apperr.CodeRejected, "connector confirmed parent required")
		}
		return nil, apperr.New(apperr.CodeRejected, "connector chain query failed")
	}
	return res, nil
}

var _ connectorChainView = (*esploraConnectorChain)(nil)
