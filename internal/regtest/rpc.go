// Package regtest is the demo Bitcoin JSON-RPC client. It is not a wallet.
package regtest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Doer is the narrow HTTP surface the RPC client uses.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client talks to a Bitcoin Core-compatible JSON-RPC endpoint.
type Client struct {
	url string
	hc  Doer
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *Error          `json:"error"`
}

// Error is a Bitcoin JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e == nil {
		return "rpc error"
	}
	return fmt.Sprintf("rpc %d: %s", e.Code, e.Message)
}

// txNotFound reports getrawtransaction's missing-tx code. Other methods may
// also return -5; only LookupTx maps that code to found=false.
func txNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e != nil && e.Code == -5
}

// Dial validates the URL and returns a client. It does not contact the node.
func Dial(rawURL string) (*Client, error) {
	return DialWith(rawURL, &http.Client{Timeout: 15 * time.Second})
}

// DialWith validates the URL and uses doer for every request.
func DialWith(rawURL string, doer Doer) (*Client, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("bitcoin rpc url required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("bitcoin rpc url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("bitcoin rpc scheme")
	}
	if doer == nil {
		return nil, fmt.Errorf("bitcoin rpc not configured")
	}
	return &Client{url: rawURL, hc: doer}, nil
}

func (c *Client) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	if c == nil || c.hc == nil {
		return nil, fmt.Errorf("bitcoin rpc not configured")
	}
	body, err := json.Marshal(rpcRequest{JSONRPC: "1.0", ID: "vault-demo", Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if u, err := url.Parse(c.url); err == nil && u.User != nil {
		pass, _ := u.User.Password()
		req.SetBasicAuth(u.User.Username(), pass)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var parsed rpcResponse
	decodeErr := json.Unmarshal(raw, &parsed)
	// Core returns application errors with HTTP 500. A valid JSON-RPC error
	// object is authoritative over the status code.
	if decodeErr == nil && parsed.Error != nil {
		return nil, parsed.Error
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("bitcoin rpc unauthorized")
		}
		return nil, fmt.Errorf("bitcoin rpc http %d", res.StatusCode)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("bitcoin rpc decode: %w", decodeErr)
	}
	return parsed.Result, nil
}

func (c *Client) GetNewAddress(ctx context.Context) (string, error) {
	raw, err := c.call(ctx, "getnewaddress")
	if err != nil {
		return "", err
	}
	var addr string
	if err := json.Unmarshal(raw, &addr); err != nil || addr == "" {
		return "", fmt.Errorf("getnewaddress")
	}
	return addr, nil
}

func (c *Client) SendToAddress(ctx context.Context, addr string, sats int64) (string, error) {
	if addr == "" || sats <= 0 {
		return "", fmt.Errorf("fund amount")
	}
	btc := float64(sats) / 1e8
	raw, err := c.call(ctx, "sendtoaddress", addr, json.Number(fmt.Sprintf("%.8f", btc)))
	if err != nil {
		return "", err
	}
	var txid string
	if err := json.Unmarshal(raw, &txid); err != nil || txid == "" {
		return "", fmt.Errorf("sendtoaddress")
	}
	return txid, nil
}

func (c *Client) GenerateToAddress(ctx context.Context, n int, addr string) error {
	if n <= 0 || n > 16 || addr == "" {
		return fmt.Errorf("mine bounds")
	}
	_, err := c.call(ctx, "generatetoaddress", n, addr)
	return err
}

func (c *Client) GetRawTransaction(ctx context.Context, txid string) ([]byte, error) {
	if txid == "" {
		return nil, fmt.Errorf("txid required")
	}
	raw, err := c.call(ctx, "getrawtransaction", txid)
	if err != nil {
		return nil, err
	}
	var hexTx string
	if err := json.Unmarshal(raw, &hexTx); err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(hexTx)
	if err != nil {
		return nil, fmt.Errorf("raw tx hex")
	}
	return b, nil
}

func (c *Client) TestMempoolAccept(ctx context.Context, rawTx []byte) (bool, string, error) {
	if len(rawTx) == 0 {
		return false, "", fmt.Errorf("raw tx required")
	}
	raw, err := c.call(ctx, "testmempoolaccept", []string{hex.EncodeToString(rawTx)})
	if err != nil {
		return false, "", err
	}
	var out []struct {
		Allowed      bool   `json:"allowed"`
		RejectReason string `json:"reject-reason"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out) != 1 {
		return false, "", fmt.Errorf("testmempoolaccept")
	}
	return out[0].Allowed, out[0].RejectReason, nil
}

func (c *Client) SendRawTransaction(ctx context.Context, rawTx []byte) (string, error) {
	if len(rawTx) == 0 {
		return "", fmt.Errorf("raw tx required")
	}
	raw, err := c.call(ctx, "sendrawtransaction", hex.EncodeToString(rawTx))
	if err != nil {
		return "", err
	}
	var txid string
	if err := json.Unmarshal(raw, &txid); err != nil || txid == "" {
		return "", fmt.Errorf("sendrawtransaction")
	}
	return txid, nil
}

func (c *Client) GetBlockCount(ctx context.Context) (int64, error) {
	raw, err := c.call(ctx, "getblockcount")
	if err != nil {
		return 0, err
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetBlockchainInfo returns the node's chain name for the regtest guard.
func (c *Client) GetBlockchainInfo(ctx context.Context) (string, error) {
	raw, err := c.call(ctx, "getblockchaininfo")
	if err != nil {
		return "", err
	}
	var out struct {
		Chain string `json:"chain"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Chain == "" {
		return "", fmt.Errorf("getblockchaininfo")
	}
	return out.Chain, nil
}

// RequireRegtest contacts the demo node with configured credentials and fails
// unless it reports the one supported chain.
func (c *Client) RequireRegtest(ctx context.Context) error {
	chain, err := c.GetBlockchainInfo(ctx)
	if err != nil {
		return err
	}
	if chain != "regtest" {
		return fmt.Errorf("bitcoin chain %s, want regtest", chain)
	}
	return nil
}

// LookupTx is the typed getrawtransaction verbose lookup. Only RPC code -5
// is "not found". Auth, warmup, timeout, transport, decode, and every other
// RPC error propagate. A mempool transaction is found with zero confirmations.
func (c *Client) LookupTx(ctx context.Context, txid string) (int64, bool, error) {
	if txid == "" {
		return 0, false, fmt.Errorf("txid required")
	}
	raw, err := c.call(ctx, "getrawtransaction", txid, true)
	if err != nil {
		if txNotFound(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	var out struct {
		Confirmations int64 `json:"confirmations"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, false, fmt.Errorf("bitcoin rpc decode: %w", err)
	}
	return out.Confirmations, true, nil
}
