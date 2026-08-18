package provider

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/regtest"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const defaultFundSats int64 = 100_000

// Chain is the demo Bitcoin control surface.
type Chain interface {
	GetNewAddress(ctx context.Context) (string, error)
	SendToAddress(ctx context.Context, addr string, sats int64) (string, error)
	GenerateToAddress(ctx context.Context, n int, addr string) error
	GetRawTransaction(ctx context.Context, txid string) ([]byte, error)
	TestMempoolAccept(ctx context.Context, rawTx []byte) (bool, string, error)
	SendRawTransaction(ctx context.Context, rawTx []byte) (string, error)
	LookupTx(ctx context.Context, txid string) (confirmations int64, found bool, err error)
}

// Demo is the gated regtest controller for funding and mining only.
// A nil Demo must not register routes. Demo never holds or releases the
// owner second-signer key.
type Demo struct {
	svc    *Service
	chain  Chain
	signer *RemoteSigner
}

// NewDemo binds a Bitcoin RPC client for gated fund and mine control.
// It fails unless svc.VaultSigner is a non-nil *RemoteSigner.
func NewDemo(svc *Service, chain Chain) (*Demo, error) {
	if svc == nil || chain == nil {
		return nil, fmt.Errorf("demo requires service and chain")
	}
	if svc.runtimeConfig().Network != deployment.NetworkRegtest {
		return nil, fmt.Errorf("demo funding and mining are regtest-only")
	}
	signer, err := requireRemoteSigner(svc.VaultSigner)
	if err != nil {
		return nil, err
	}
	return &Demo{svc: svc, chain: chain, signer: signer}, nil
}

func requireRemoteSigner(s Signer) (*RemoteSigner, error) {
	rs, ok := s.(*RemoteSigner)
	if !ok || rs == nil || isNilInterface(rs.Client) {
		return nil, fmt.Errorf("demo requires a non-nil RemoteSigner client")
	}
	return rs, nil
}

// Chain exposes the Bitcoin control surface for Publish.
func (d *Demo) Chain() Chain {
	if d == nil {
		return nil
	}
	return d.chain
}

// DialBitcoinRPC dials Bitcoin JSON-RPC and requires an authenticated
// getblockchaininfo chain of exactly "regtest". Publish uses this
// independently of Demo.
func DialBitcoinRPC(ctx context.Context, rpcURL string) (Chain, error) {
	return dialBitcoin(ctx, rpcURL, nil)
}

func dialBitcoin(ctx context.Context, rpcURL string, doer regtest.Doer) (Chain, error) {
	var (
		cli *regtest.Client
		err error
	)
	if doer == nil {
		cli, err = regtest.Dial(rpcURL)
	} else {
		cli, err = regtest.DialWith(rpcURL, doer)
	}
	if err != nil {
		return nil, err
	}
	if err := cli.RequireRegtest(ctx); err != nil {
		return nil, err
	}
	return cli, nil
}

// NewRPCDemo dials Bitcoin JSON-RPC and constructs Demo (RemoteSigner required).
func NewRPCDemo(svc *Service, rpcURL string) (*Demo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cli, err := DialBitcoinRPC(ctx, rpcURL)
	if err != nil {
		return nil, err
	}
	return NewDemo(svc, cli)
}

type demoInfo struct {
	Demo                  bool   `json:"demo"`
	Network               string `json:"network"`
	SignerMode            string `json:"signerMode"`
	RemoteSignerSuccesses uint64 `json:"remoteSignerSuccesses"`
	Note                  string `json:"note"`
}

func (d *Demo) info() demoInfo {
	mode := "invalid"
	if current, ok := d.svc.VaultSigner.(*RemoteSigner); ok && current == d.signer {
		mode = "remote"
	}
	return demoInfo{
		Demo:                  true,
		Network:               d.svc.runtimeConfig().Network,
		SignerMode:            mode,
		RemoteSignerSuccesses: d.signer.SuccessfulCalls(),
		Note:                  "demo control is fail-closed unless VAULT_DEMO=1; fund/mine only; RemoteSigner only",
	}
}

type fundResult struct {
	Txid          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	PrevTxHex     string `json:"prevTxHex"`
	Amount        int64  `json:"amount"`
	Address       string `json:"address"`
	SinkAddress   string `json:"sinkAddress"`
	SinkScript    string `json:"sinkScript"`
	Confirmations int64  `json:"confirmations"`
}

func (d *Demo) fund(ctx context.Context, amount int64) (*fundResult, error) {
	if d == nil || d.chain == nil {
		return nil, fmt.Errorf("demo disabled")
	}
	op := d.svc.enrolled().Operational
	if op == nil {
		return nil, fmt.Errorf("not enrolled")
	}
	if amount <= 0 {
		amount = defaultFundSats
	}
	sinkAddr, err := d.chain.GetNewAddress(ctx)
	if err != nil {
		return nil, err
	}
	sinkScript, err := addressScript(sinkAddr)
	if err != nil {
		return nil, err
	}
	txid, err := d.chain.SendToAddress(ctx, op.Address, amount)
	if err != nil {
		return nil, err
	}
	if err := d.chain.GenerateToAddress(ctx, 1, sinkAddr); err != nil {
		return nil, err
	}
	raw, err := d.chain.GetRawTransaction(ctx, txid)
	if err != nil {
		return nil, err
	}
	prev := wire.NewMsgTx(2)
	if err := prev.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("fund tx: %w", err)
	}
	var vout uint32
	var got int64
	found := false
	for i, out := range prev.TxOut {
		if bytes.Equal(out.PkScript, op.PkScript) {
			vout = uint32(i)
			got = out.Value
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("fund did not pay the operational address")
	}
	conf, found, err := d.chain.LookupTx(ctx, txid)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("fund tx not found")
	}
	return &fundResult{
		Txid:          txid,
		Vout:          vout,
		PrevTxHex:     hex.EncodeToString(raw),
		Amount:        got,
		Address:       op.Address,
		SinkAddress:   sinkAddr,
		SinkScript:    hex.EncodeToString(sinkScript),
		Confirmations: conf,
	}, nil
}

func (d *Demo) mine(ctx context.Context, blocks int) error {
	if d == nil || d.chain == nil {
		return fmt.Errorf("demo disabled")
	}
	if blocks <= 0 {
		blocks = 1
	}
	addr, err := d.chain.GetNewAddress(ctx)
	if err != nil {
		return err
	}
	return d.chain.GenerateToAddress(ctx, blocks, addr)
}

func addressScript(addr string) ([]byte, error) {
	a, err := btcutil.DecodeAddress(addr, &chaincfg.RegressionNetParams)
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(a)
}
