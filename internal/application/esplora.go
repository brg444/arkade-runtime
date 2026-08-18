package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// EsploraBroadcaster publishes and observes transactions through a pinned
// Mutinynet Esplora endpoint. It deliberately does not implement demo wallet
// or mining methods.
type EsploraBroadcaster struct {
	base string
	hc   httpDoer
}

// DialEsplora contacts /block-height/1 and refuses generic or wrong signets.
func DialEsplora(ctx context.Context, rawURL, network string) (*EsploraBroadcaster, error) {
	return dialEsplora(ctx, rawURL, network, newEsploraHTTPClient())
}

func newEsploraHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("esplora redirects are disabled")
		},
	}
}

func dialEsplora(ctx context.Context, rawURL, network string, hc httpDoer) (*EsploraBroadcaster, error) {
	if network != deployment.NetworkMutinynet {
		return nil, fmt.Errorf("esplora deployment is mutinynet-only")
	}
	if hc == nil {
		return nil, fmt.Errorf("esplora client required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("mutinynet esplora requires a clean https base url")
	}
	b := &EsploraBroadcaster{base: strings.TrimRight(rawURL, "/"), hc: hc}
	height, want, err := (deployment.Config{Network: network}).BitcoinCheckpoint()
	if err != nil {
		return nil, err
	}
	got, err := b.getText(ctx, "/block-height/"+strconv.FormatInt(height, 10), 128)
	if err != nil {
		return nil, fmt.Errorf("mutinynet checkpoint: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(got)) != want {
		return nil, fmt.Errorf("esplora checkpoint %d is %s, want %s", height, strings.TrimSpace(got), want)
	}
	return b, nil
}

func (e *EsploraBroadcaster) Broadcast(ctx context.Context, rawTx []byte) (string, error) {
	if e == nil || e.hc == nil || len(rawTx) == 0 {
		return "", fmt.Errorf("esplora publisher not configured")
	}
	want, err := rawTxid(rawTx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/tx", strings.NewReader(hex.EncodeToString(rawTx)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/plain")
	res, err := e.hc.Do(req)
	if err != nil {
		return "", err
	}
	body, readErr := readEsploraBody(res, 1024)
	if readErr != nil {
		return "", readErr
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("esplora broadcast http %d: %s", res.StatusCode, strings.TrimSpace(body))
	}
	got := strings.ToLower(strings.TrimSpace(body))
	if got != want {
		return "", fmt.Errorf("esplora returned txid mismatch")
	}
	return got, nil
}

func (e *EsploraBroadcaster) Lookup(ctx context.Context, txid string) (int64, bool, error) {
	if e == nil || e.hc == nil {
		return 0, false, fmt.Errorf("esplora publisher not configured")
	}
	if err := requireTxid(txid); err != nil {
		return 0, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base+"/tx/"+txid+"/status", nil)
	if err != nil {
		return 0, false, err
	}
	res, err := e.hc.Do(req)
	if err != nil {
		return 0, false, err
	}
	if res.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1024))
		_ = res.Body.Close()
		return 0, false, nil
	}
	body, err := readEsploraBody(res, 4096)
	if err != nil {
		return 0, false, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return 0, false, fmt.Errorf("esplora status http %d", res.StatusCode)
	}
	var status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockHeight int64 `json:"block_height"`
	}
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		return 0, false, fmt.Errorf("esplora status: %w", err)
	}
	if !status.Confirmed {
		return 0, true, nil
	}
	if status.BlockHeight <= 0 {
		return 0, false, fmt.Errorf("esplora confirmed status missing block height")
	}
	tipText, err := e.getText(ctx, "/blocks/tip/height", 64)
	if err != nil {
		return 0, false, err
	}
	tip, err := strconv.ParseInt(strings.TrimSpace(tipText), 10, 64)
	if err != nil || status.BlockHeight < 0 || tip < status.BlockHeight {
		return 0, false, fmt.Errorf("esplora confirmation height")
	}
	return tip - status.BlockHeight + 1, true, nil
}

func (e *EsploraBroadcaster) getText(ctx context.Context, path string, limit int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base+path, nil)
	if err != nil {
		return "", err
	}
	res, err := e.hc.Do(req)
	if err != nil {
		return "", err
	}
	body, err := readEsploraBody(res, limit)
	if err != nil {
		return "", err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("esplora http %d", res.StatusCode)
	}
	return body, nil
}

func readEsploraBody(res *http.Response, limit int64) (string, error) {
	if res == nil || res.Body == nil {
		return "", fmt.Errorf("empty esplora response")
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(res.Body, limit+1))
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", fmt.Errorf("esplora response too large")
	}
	return buf.String(), nil
}

func requireTxid(txid string) error {
	if len(txid) != 64 || txid != strings.ToLower(txid) {
		return fmt.Errorf("txid")
	}
	raw, err := hex.DecodeString(txid)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("txid")
	}
	return nil
}
