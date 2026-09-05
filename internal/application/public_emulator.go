package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

const (
	publicEmulatorTimeout      = 15 * time.Second
	publicEmulatorInfoLimit    = 16 * 1024
	publicEmulatorSigningLimit = 512 * 1024
	publicEmulatorPSBTLimit    = 384 * 1024
)

// PublicEmulatorIdentity is the exact release-pinned remote identity used by
// one enrolled descriptor. Network identity is established separately by the
// checkpoint-pinned Mutinynet publisher because the current public Emulator
// GetInfo response does not expose its arkd network.
type PublicEmulatorIdentity struct {
	Origin  string
	Version string
	BasePub *btcec.PublicKey
}

// DialPublicEmulator constructs the narrow outbound signing transport and
// verifies GetInfo against the release's exact base key and version allowlist.
// It never trusts GetInfo as TOFU enrollment input.
func DialPublicEmulator(
	ctx context.Context,
	rawOrigin string,
	expectedBase *btcec.PublicKey,
	allowedVersions []string,
	allowActiveDeprecated bool,
) (Signer, PublicEmulatorIdentity, error) {
	return dialPublicEmulator(ctx, rawOrigin, expectedBase, allowedVersions, allowActiveDeprecated, newPublicEmulatorHTTPClient())
}

func newPublicEmulatorHTTPClient() *http.Client {
	return &http.Client{
		Timeout: publicEmulatorTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("public arkade emulator redirects are disabled")
		},
	}
}

func dialPublicEmulator(
	ctx context.Context,
	rawOrigin string,
	expectedBase *btcec.PublicKey,
	allowedVersions []string,
	allowActiveDeprecated bool,
	hc httpDoer,
) (Signer, PublicEmulatorIdentity, error) {
	if expectedBase == nil {
		return nil, PublicEmulatorIdentity{}, fmt.Errorf("public arkade emulator base key must be release-pinned")
	}
	versions, err := canonicalVersionAllowlist(allowedVersions)
	if err != nil {
		return nil, PublicEmulatorIdentity{}, err
	}
	origin, err := CanonicalHTTPSOrigin(rawOrigin)
	if err != nil {
		return nil, PublicEmulatorIdentity{}, err
	}
	if hc == nil {
		return nil, PublicEmulatorIdentity{}, fmt.Errorf("public arkade emulator HTTP client required")
	}
	client := &publicEmulatorClient{origin: origin, hc: hc}
	info, err := client.getInfo(ctx)
	if err != nil {
		return nil, PublicEmulatorIdentity{}, fmt.Errorf("public arkade emulator info: %w", err)
	}
	if _, ok := versions[info.Version]; !ok {
		return nil, PublicEmulatorIdentity{}, fmt.Errorf("signing service version is not allowlisted")
	}
	current, err := parseStrictCompressedPub(info.SignerPubkey)
	if err != nil {
		return nil, PublicEmulatorIdentity{}, fmt.Errorf("public arkade emulator signer pubkey: %w", err)
	}
	matched := bytes.Equal(current.SerializeCompressed(), expectedBase.SerializeCompressed())
	seen := map[string]struct{}{string(current.SerializeCompressed()): {}}
	for i, encoded := range info.DeprecatedSignerPubkeys {
		deprecated, err := parseStrictCompressedPub(encoded)
		if err != nil {
			return nil, PublicEmulatorIdentity{}, fmt.Errorf("public arkade emulator deprecated signer pubkey %d: %w", i, err)
		}
		serialized := deprecated.SerializeCompressed()
		if _, duplicate := seen[string(serialized)]; duplicate {
			return nil, PublicEmulatorIdentity{}, fmt.Errorf("public arkade emulator advertised duplicate signer keys")
		}
		seen[string(serialized)] = struct{}{}
		if allowActiveDeprecated && bytes.Equal(serialized, expectedBase.SerializeCompressed()) {
			matched = true
		}
	}
	if !matched {
		return nil, PublicEmulatorIdentity{}, fmt.Errorf("public arkade emulator signer pubkey does not match the release pin")
	}
	return &publicEmulatorSigner{client: client}, PublicEmulatorIdentity{
		Origin: origin, Version: info.Version, BasePub: expectedBase,
	}, nil
}

func canonicalVersionAllowlist(values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one public arkade emulator version must be allowlisted")
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
			return nil, fmt.Errorf("public arkade emulator version allowlist contains a non-canonical value")
		}
		if _, exists := out[value]; exists {
			return nil, fmt.Errorf("public arkade emulator version allowlist contains a duplicate")
		}
		out[value] = struct{}{}
	}
	return out, nil
}

// CanonicalHTTPSOrigin validates a private transport locator without contacting it.
func CanonicalHTTPSOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("public arkade emulator requires a canonical https origin")
	}
	if u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("public arkade emulator URL must be an origin without credentials, path, query, or fragment")
	}
	// The release pin uses the default HTTPS port and a canonical DNS name.
	// Reject empty, explicit, IPv6, and otherwise browser-normalized authority
	// forms instead of accepting two textual identities for the same endpoint.
	if u.Host != u.Hostname() || strings.HasSuffix(u.Hostname(), ".") || strings.IndexFunc(u.Hostname(), func(r rune) bool { return r > 127 }) >= 0 {
		return "", fmt.Errorf("public arkade emulator origin must use a canonical ASCII hostname and implicit HTTPS port")
	}
	canonical := "https://" + strings.ToLower(u.Host)
	if raw != canonical {
		return "", fmt.Errorf("public arkade emulator origin must be canonical lowercase and omit the default port")
	}
	return canonical, nil
}

type publicEmulatorClient struct {
	origin string
	hc     httpDoer
}

// publicEmulatorSigner is the production authorizer's sole outbound signer
// adapter. It can reach only the release-pinned HTTP client's onchain method;
// the caller's signExactStage wrapper independently reduces its response to
// one expected signature delta.
type publicEmulatorSigner struct {
	client *publicEmulatorClient
}

func (s *publicEmulatorSigner) Sign(ctx context.Context, packet *psbt.Packet) (*psbt.Packet, error) {
	if s == nil || s.client == nil || packet == nil {
		return nil, fmt.Errorf("public arkade emulator signer not configured")
	}
	encoded, err := packet.B64Encode()
	if err != nil {
		return nil, err
	}
	signed, err := s.client.signPinnedOnchain(ctx, encoded)
	if err != nil {
		return nil, err
	}
	out, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		return nil, fmt.Errorf("public arkade emulator signed PSBT: %w", err)
	}
	return out, nil
}

type publicEmulatorInfoResponse struct {
	Version                 string   `json:"version"`
	SignerPubkey            string   `json:"signerPubkey"`
	DeprecatedSignerPubkeys []string `json:"deprecatedSignerPubkeys"`
}

func (c *publicEmulatorClient) getInfo(ctx context.Context) (publicEmulatorInfoResponse, error) {
	var out publicEmulatorInfoResponse
	if err := c.call(ctx, http.MethodGet, "/v1/info", nil, &out, publicEmulatorInfoLimit); err != nil {
		return publicEmulatorInfoResponse{}, err
	}
	if out.Version == "" || out.SignerPubkey == "" {
		return publicEmulatorInfoResponse{}, fmt.Errorf("incomplete GetInfo response")
	}
	return out, nil
}

func (c *publicEmulatorClient) signPinnedOnchain(ctx context.Context, encoded string) (string, error) {
	if c == nil || c.hc == nil {
		return "", fmt.Errorf("public arkade emulator client not configured")
	}
	if encoded == "" || len(encoded) > publicEmulatorPSBTLimit {
		return "", fmt.Errorf("public arkade emulator PSBT is empty or too large")
	}
	var out struct {
		SignedTx string `json:"signedTx"`
	}
	if err := c.call(ctx, http.MethodPost, "/v1/onchain-tx", struct {
		Tx string `json:"tx"`
	}{Tx: encoded}, &out, publicEmulatorSigningLimit); err != nil {
		return "", err
	}
	if out.SignedTx == "" || len(out.SignedTx) > publicEmulatorPSBTLimit {
		return "", fmt.Errorf("public arkade emulator returned an empty or oversized signed PSBT")
	}
	return out.SignedTx, nil
}

func (c *publicEmulatorClient) call(
	ctx context.Context,
	method, path string,
	requestBody, responseBody any,
	responseLimit int64,
) error {
	if c == nil || c.hc == nil || c.origin == "" {
		return fmt.Errorf("public arkade emulator client not configured")
	}
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		if len(encoded) > publicEmulatorSigningLimit {
			return fmt.Errorf("public arkade emulator request too large")
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return fmt.Errorf("signing service request could not be created")
	}
	req.Header.Set("Accept", "application/json")
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("signing service transport unavailable")
	}
	if res == nil || res.Body == nil {
		return fmt.Errorf("empty public arkade emulator response")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("signing service HTTP %d", res.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("public arkade emulator response must be application/json")
	}
	raw, err := readBoundedResponse(res.Body, responseLimit)
	if err != nil {
		return fmt.Errorf("signing service response could not be read within its limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(responseBody); err != nil {
		return fmt.Errorf("signing service returned invalid JSON")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("public arkade emulator response contains trailing data")
	}
	return nil
}

func readBoundedResponse(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("invalid response bound")
	}
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("public arkade emulator response too large")
	}
	return raw, nil
}

func parseStrictCompressedPub(encoded string) (*btcec.PublicKey, error) {
	if len(encoded) != 66 || encoded != strings.ToLower(encoded) {
		return nil, fmt.Errorf("must be canonical 33-byte compressed lowercase hex")
	}
	raw, err := decodeHex(encoded)
	if err != nil || len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		return nil, fmt.Errorf("must be canonical 33-byte compressed lowercase hex")
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil || !bytes.Equal(pub.SerializeCompressed(), raw) {
		return nil, fmt.Errorf("invalid compressed secp256k1 key")
	}
	return pub, nil
}
