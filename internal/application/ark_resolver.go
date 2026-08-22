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
	"net/url"
	"strconv"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/ports"
)

const (
	arkResolverTimeout    = 15 * time.Second
	arkResolverInfoLimit  = 16 * 1024
	arkResolverVtxosLimit = 512 * 1024
)

type arkResolver struct {
	origin     string
	hc         httpDoer
	network    string
	checkpoint []byte
	signerPub  []byte
}

// DialArkResolver constructs the release-pinned Mutinynet ark indexer client.
// The origin is baked into the binary; there is no argument or env override.
func DialArkResolver(ctx context.Context, network string) (ports.ArkResolver, error) {
	return dialArkResolver(ctx, deployment.MutinynetArkIndexerOrigin, network, newArkResolverHTTPClient())
}

func newArkResolverHTTPClient() *http.Client {
	return &http.Client{
		Timeout: arkResolverTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("ark indexer redirects are disabled")
		},
	}
}

func dialArkResolver(ctx context.Context, rawOrigin, network string, hc httpDoer) (ports.ArkResolver, error) {
	if network != deployment.NetworkMutinynet {
		return nil, fmt.Errorf("ark indexer network %q is not %s", network, deployment.NetworkMutinynet)
	}
	height, hash, err := (deployment.Config{Network: network}).BitcoinCheckpoint()
	if err != nil {
		return nil, err
	}
	if height != 1 || hash != deployment.MutinynetCheckpoint1 {
		return nil, fmt.Errorf("ark indexer checkpoint is %d:%s, want 1:%s", height, hash, deployment.MutinynetCheckpoint1)
	}
	origin, err := canonicalHTTPSOrigin(rawOrigin)
	if err != nil {
		return nil, err
	}
	if origin != deployment.MutinynetArkIndexerOrigin {
		return nil, fmt.Errorf("ark indexer origin must be the release pin")
	}
	if hc == nil {
		return nil, fmt.Errorf("ark indexer HTTP client required")
	}
	client := &arkResolver{origin: origin, hc: hc, network: deployment.NetworkMutinynet}
	info, err := client.getInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("ark indexer info: %w", err)
	}
	gotNetwork := strings.TrimSpace(info.Network)
	if gotNetwork != deployment.NetworkMutinynet {
		return nil, fmt.Errorf("ark indexer network %q does not match %s", gotNetwork, deployment.NetworkMutinynet)
	}
	checkpoint, err := decodeHex(strings.TrimSpace(info.CheckpointTapscript))
	if err != nil || len(checkpoint) == 0 {
		return nil, fmt.Errorf("incomplete ark indexer GetInfo")
	}
	signerPub, err := decodeHex(strings.TrimSpace(info.SignerPubkey))
	if err != nil {
		return nil, fmt.Errorf("incomplete ark indexer GetInfo")
	}
	if err := validateArkResolverPolicy(network, checkpoint, signerPub); err != nil {
		return nil, err
	}
	client.checkpoint = checkpoint
	client.signerPub = signerPub
	return client, nil
}

// validateArkResolverPolicy prevents a remote Operator from redefining the
// checkpoint fallback that the VaultCosigner will authorize.
func validateArkResolverPolicy(network string, checkpoint, signerPub []byte) error {
	if network != deployment.NetworkMutinynet {
		return fmt.Errorf("unsupported Operator policy network %q", network)
	}
	wantSigner, err := hex.DecodeString(deployment.MutinynetOperatorSignerPubHex)
	if err != nil || !bytes.Equal(signerPub, wantSigner) {
		return fmt.Errorf("Operator signer does not match the release policy")
	}
	wantCheckpoint, err := hex.DecodeString(deployment.MutinynetCheckpointTapscriptHex)
	if err != nil || !bytes.Equal(checkpoint, wantCheckpoint) {
		return fmt.Errorf("checkpoint tapscript does not match the release policy")
	}
	closure, err := arkscript.DecodeClosure(checkpoint)
	if err != nil {
		return fmt.Errorf("checkpoint tapscript: %w", err)
	}
	csv, ok := closure.(*arkscript.CSVMultisigClosure)
	if !ok || csv.Type != arkscript.MultisigTypeChecksig || len(csv.PubKeys) != 1 {
		return fmt.Errorf("checkpoint closure does not match the release policy")
	}
	if csv.Locktime.Type != arklib.LocktimeTypeSecond || csv.Locktime.Value != deployment.MutinynetCheckpointDelaySeconds {
		return fmt.Errorf("checkpoint delay does not match the release policy")
	}
	wantForfeit, err := hex.DecodeString(deployment.MutinynetCheckpointForfeitPubHex)
	if err != nil || !bytes.Equal(csv.PubKeys[0].SerializeCompressed(), wantForfeit) {
		return fmt.Errorf("checkpoint key does not match the release policy")
	}
	return nil
}

func (r *arkResolver) Network() string {
	if r == nil {
		return ""
	}
	return r.network
}

func (r *arkResolver) CheckpointTapscript() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.checkpoint)
}

func (r *arkResolver) OperatorSignerPub() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.signerPub)
}

func (r *arkResolver) ReservedSpentByArkTxid(ctx context.Context, pkScript []byte, reserved []ports.ResolvedVtxo, arkTxid string) error {
	if len(reserved) == 0 {
		return fmt.Errorf("reserved outpoints required")
	}
	if err := requireTxid(strings.ToLower(strings.TrimSpace(arkTxid))); err != nil {
		return fmt.Errorf("arkTxid")
	}
	listed, err := r.listVtxos(ctx, pkScript, false)
	if err != nil {
		return err
	}
	byOut := make(map[string]indexerVtxo, len(listed))
	for _, vtxo := range listed {
		if vtxo.Outpoint.Vout == nil {
			continue
		}
		if err := requireTxid(vtxo.Outpoint.Txid); err != nil {
			continue
		}
		byOut[vtxo.Outpoint.Txid+":"+strconv.FormatUint(uint64(*vtxo.Outpoint.Vout), 10)] = vtxo
	}
	wantTx := strings.ToLower(strings.TrimSpace(arkTxid))
	for _, want := range reserved {
		got, ok := byOut[want.Txid+":"+strconv.FormatUint(uint64(want.Vout), 10)]
		if !ok {
			return fmt.Errorf("reserved outpoint missing from indexer")
		}
		if !got.IsSpent {
			return fmt.Errorf("reserved outpoints not spent")
		}
		// arkd records the checkpoint transaction ID in spentBy and the
		// offchain transaction ID in arkTxid. Finalization is bound to the
		// latter; comparing spentBy to an Arkade transaction ID rejects every
		// otherwise valid collaborative spend.
		if strings.ToLower(strings.TrimSpace(got.ArkTxid)) != wantTx {
			return fmt.Errorf("reserved outpoint not spent by ark txid")
		}
	}
	return nil
}

func (r *arkResolver) ChangeVtxoFromArkTx(ctx context.Context, changeScript []byte, arkTxid string, vout uint32, valueSats uint64) error {
	if err := requireTxid(strings.ToLower(strings.TrimSpace(arkTxid))); err != nil {
		return fmt.Errorf("arkTxid")
	}
	listed, err := r.listVtxos(ctx, changeScript, false)
	if err != nil {
		return err
	}
	wantTx := strings.ToLower(strings.TrimSpace(arkTxid))
	for _, vtxo := range listed {
		if vtxo.Outpoint.Vout == nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(vtxo.Outpoint.Txid)) != wantTx || *vtxo.Outpoint.Vout != vout {
			continue
		}
		item, err := parseResolvedVtxo(vtxo, changeScript)
		if err != nil {
			return err
		}
		if item.ValueSats != valueSats {
			return fmt.Errorf("change vtxo amount")
		}
		return nil
	}
	return fmt.Errorf("change vtxo not yet projected")
}

func (r *arkResolver) SpendableVtxos(ctx context.Context, pkScript []byte) ([]ports.ResolvedVtxo, error) {
	listed, err := r.listVtxos(ctx, pkScript, true)
	if err != nil {
		return nil, err
	}
	resolved := make([]ports.ResolvedVtxo, 0, len(listed))
	for i, vtxo := range listed {
		if vtxo.IsSpent {
			continue
		}
		item, err := parseResolvedVtxo(vtxo, pkScript)
		if err != nil {
			return nil, fmt.Errorf("ark indexer vtxo %d: %w", i, err)
		}
		resolved = append(resolved, item)
	}
	return resolved, nil
}

func (r *arkResolver) listVtxos(ctx context.Context, pkScript []byte, spendableOnly bool) ([]indexerVtxo, error) {
	if r == nil || r.hc == nil || r.origin == "" {
		return nil, fmt.Errorf("ark indexer not configured")
	}
	if len(pkScript) == 0 {
		return nil, fmt.Errorf("pkScript is required")
	}
	query := url.Values{}
	query.Set("scripts", hex.EncodeToString(pkScript))
	if spendableOnly {
		query.Set("spendableOnly", "true")
	}
	var out struct {
		Vtxos []indexerVtxo `json:"vtxos"`
	}
	if err := r.getJSON(ctx, "/v1/indexer/vtxos?"+query.Encode(), &out, arkResolverVtxosLimit); err != nil {
		return nil, err
	}
	return out.Vtxos, nil
}

type arkIndexerInfo struct {
	Network             string `json:"network"`
	CheckpointTapscript string `json:"checkpointTapscript"`
	SignerPubkey        string `json:"signerPubkey"`
}

type indexerOutpoint struct {
	Txid string  `json:"txid"`
	Vout *uint32 `json:"vout"`
}

type indexerVtxo struct {
	Outpoint indexerOutpoint `json:"outpoint"`
	Amount   json.RawMessage `json:"amount"`
	Script   string          `json:"script"`
	IsSpent  bool            `json:"isSpent"`
	SpentBy  string          `json:"spentBy"`
	ArkTxid  string          `json:"arkTxid"`
}

func (r *arkResolver) getInfo(ctx context.Context) (arkIndexerInfo, error) {
	var out arkIndexerInfo
	if err := r.getJSON(ctx, "/v1/info", &out, arkResolverInfoLimit); err != nil {
		return arkIndexerInfo{}, err
	}
	if strings.TrimSpace(out.Network) == "" {
		return arkIndexerInfo{}, fmt.Errorf("network missing")
	}
	if strings.TrimSpace(out.CheckpointTapscript) == "" {
		return arkIndexerInfo{}, fmt.Errorf("incomplete GetInfo response")
	}
	return out, nil
}

func (r *arkResolver) getJSON(ctx context.Context, path string, dest any, limit int64) error {
	if r == nil || r.hc == nil || r.origin == "" {
		return fmt.Errorf("ark indexer not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.origin+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := r.hc.Do(req)
	if err != nil {
		return err
	}
	if res == nil || res.Body == nil {
		return fmt.Errorf("empty ark indexer response")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		detail, _ := readBoundedResponse(res.Body, 4096)
		return fmt.Errorf("ark indexer HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(detail)))
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("ark indexer response must be application/json")
	}
	raw, err := readBoundedResponse(res.Body, limit)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("ark indexer response: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("ark indexer response contains trailing data")
	}
	return nil
}

func parseResolvedVtxo(vtxo indexerVtxo, pkScript []byte) (ports.ResolvedVtxo, error) {
	if vtxo.Outpoint.Vout == nil {
		return ports.ResolvedVtxo{}, fmt.Errorf("missing outpoint")
	}
	if err := requireTxid(vtxo.Outpoint.Txid); err != nil {
		return ports.ResolvedVtxo{}, fmt.Errorf("outpoint txid")
	}
	script, err := decodeHex(vtxo.Script)
	if err != nil || !bytes.Equal(script, pkScript) {
		return ports.ResolvedVtxo{}, fmt.Errorf("script does not match requested pkScript")
	}
	amount, err := parseUint64Sats(vtxo.Amount)
	if err != nil {
		return ports.ResolvedVtxo{}, err
	}
	return ports.ResolvedVtxo{
		Txid:      vtxo.Outpoint.Txid,
		Vout:      *vtxo.Outpoint.Vout,
		ValueSats: amount,
		Script:    bytes.Clone(script),
	}, nil
}

func parseUint64Sats(raw json.RawMessage) (uint64, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, fmt.Errorf("amount is missing")
	}
	var asNumber json.Number
	if err := json.Unmarshal(raw, &asNumber); err == nil {
		return parseCanonicalUint64Sats(string(asNumber))
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err != nil {
		return 0, fmt.Errorf("amount")
	}
	return parseCanonicalUint64Sats(asString)
}

func parseCanonicalUint64Sats(s string) (uint64, error) {
	if s == "" || strings.ContainsAny(s, ".eE+") {
		return 0, fmt.Errorf("amount overflow")
	}
	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("amount overflow")
	}
	return u, nil
}
