package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestPublicEmulatorPinsCurrentForEnrollmentAndActiveDeprecatedForRestart(t *testing.T) {
	current, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	deprecated, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://emulator.example.com"
	const version = "v-reviewed"
	info := fmt.Sprintf(
		`{"version":%q,"signerPubkey":%q,"deprecatedSignerPubkeys":[%q]}`,
		version,
		hex.EncodeToString(current.PubKey().SerializeCompressed()),
		hex.EncodeToString(deprecated.PubKey().SerializeCompressed()),
	)
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.String() != origin+"/v1/info" {
			t.Fatalf("unexpected info request: %s %s", req.Method, req.URL)
		}
		return jsonResponse(http.StatusOK, info), nil
	})

	if _, identity, err := dialPublicEmulator(
		context.Background(), origin, current.PubKey(), []string{version}, false, doer,
	); err != nil || !identity.BasePub.IsEqual(current.PubKey()) {
		t.Fatalf("fresh enrollment rejected current pin: identity=%+v err=%v", identity, err)
	}
	if _, _, err := dialPublicEmulator(
		context.Background(), origin, deprecated.PubKey(), []string{version}, false, doer,
	); err == nil {
		t.Fatal("fresh enrollment accepted an actively deprecated key")
	}
	if _, identity, err := dialPublicEmulator(
		context.Background(), origin, deprecated.PubKey(), []string{version}, true, doer,
	); err != nil || !identity.BasePub.IsEqual(deprecated.PubKey()) {
		t.Fatalf("restart rejected its exact actively deprecated pin: identity=%+v err=%v", identity, err)
	}
	if _, _, err := dialPublicEmulator(
		context.Background(), origin, unknown.PubKey(), []string{version}, true, doer,
	); err == nil {
		t.Fatal("restart substituted a remotely advertised identity for its exact pin")
	}
}

func TestPublicEmulatorRejectsMalformedIdentityAndTransport(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(key.PubKey().SerializeCompressed())
	const origin = "https://emulator.example.com"
	const version = "v-reviewed"

	for name, body := range map[string]string{
		"unknown field":        fmt.Sprintf(`{"version":%q,"signerPubkey":%q,"extra":true}`, version, encoded),
		"trailing data":        fmt.Sprintf(`{"version":%q,"signerPubkey":%q} {}`, version, encoded),
		"malformed deprecated": fmt.Sprintf(`{"version":%q,"signerPubkey":%q,"deprecatedSignerPubkeys":["02"]}`, version, encoded),
		"duplicate current":    fmt.Sprintf(`{"version":%q,"signerPubkey":%q,"deprecatedSignerPubkeys":[%q]}`, version, encoded, encoded),
	} {
		t.Run(name, func(t *testing.T) {
			doer := rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, body), nil
			})
			if _, _, err := dialPublicEmulator(
				context.Background(), origin, key.PubKey(), []string{version}, true, doer,
			); err == nil {
				t.Fatal("malformed public Emulator identity accepted")
			}
		})
	}

	for _, raw := range []string{
		"http://emulator.example.com",
		"https://Emulator.example.com",
		"https://emulator.example.com/",
		"https://emulator.example.com:443",
		"https://emulator.example.com:",
		"https://emulator.example.com:08443",
		"https://emulator.example.com.",
		"https://user@emulator.example.com",
	} {
		if _, _, err := dialPublicEmulator(
			context.Background(), raw, key.PubKey(), []string{version}, false,
			rpcDoerFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid origin reached the network")
				return nil, nil
			}),
		); err == nil {
			t.Fatalf("non-canonical origin accepted: %q", raw)
		}
	}

	req, err := http.NewRequest(http.MethodGet, "http://attacker.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := newPublicEmulatorHTTPClient().CheckRedirect(req, nil); err == nil {
		t.Fatal("public Emulator redirect accepted")
	}
}

func TestPublicEmulatorSubmitUsesOnlyBoundedExactEndpoint(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://emulator.example.com"
	const version = "v-reviewed"
	const submitted = "cHNidP8BAA=="
	const signed = "cHNidP8BAQE="
	doer := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			if req.URL.String() != origin+"/v1/info" {
				t.Fatalf("unexpected info endpoint: %s", req.URL)
			}
			body := fmt.Sprintf(
				`{"version":%q,"signerPubkey":%q,"deprecatedSignerPubkeys":[]}`,
				version, hex.EncodeToString(key.PubKey().SerializeCompressed()),
			)
			return jsonResponse(http.StatusOK, body), nil
		case http.MethodPost:
			if req.URL.String() != origin+"/v1/onchain-tx" {
				t.Fatalf("unexpected signing endpoint: %s", req.URL)
			}
			if req.Header.Get("Accept") != "application/json" || req.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected headers: %#v", req.Header)
			}
			var body struct {
				Tx string `json:"tx"`
			}
			dec := json.NewDecoder(req.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&body); err != nil || body.Tx != submitted {
				t.Fatalf("unexpected request body: %+v err=%v", body, err)
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"signedTx":%q}`, signed)), nil
		default:
			t.Fatalf("unexpected method: %s", req.Method)
			return nil, nil
		}
	})
	signer, _, err := dialPublicEmulator(
		context.Background(), origin, key.PubKey(), []string{version}, false, doer,
	)
	if err != nil {
		t.Fatal(err)
	}
	remote, ok := signer.(*publicEmulatorSigner)
	if !ok || remote.client == nil {
		t.Fatalf("dial returned %T, want narrow public signer", signer)
	}
	got, err := remote.client.signPinnedOnchain(context.Background(), submitted)
	if err != nil || got != signed {
		t.Fatalf("submit result=%q err=%v", got, err)
	}
}

func TestPublicEmulatorSubmitRejectsUnboundedOrMalformedResponses(t *testing.T) {
	client := &publicEmulatorClient{
		origin: "https://emulator.example.com",
		hc: rpcDoerFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"signedTx":"`+strings.Repeat("a", publicEmulatorPSBTLimit+1)+`"}`), nil
		}),
	}
	if _, err := client.signPinnedOnchain(context.Background(), strings.Repeat("a", publicEmulatorPSBTLimit+1)); err == nil {
		t.Fatal("oversized submitted PSBT accepted")
	}
	if _, err := client.signPinnedOnchain(context.Background(), "cHNidA=="); err == nil {
		t.Fatal("oversized signed PSBT response accepted")
	}

	client.hc = rpcDoerFunc(func(*http.Request) (*http.Response, error) {
		res := jsonResponse(http.StatusOK, `{"signedTx":"cHNidA=="}`)
		res.Header.Set("Content-Type", "text/plain")
		return res, nil
	})
	if _, err := client.signPinnedOnchain(context.Background(), "cHNidA=="); err == nil {
		t.Fatal("non-JSON signing response accepted")
	}
}

func jsonResponse(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestSignerErrorsDoNotDiscloseEndpointOrUpstreamContent(t *testing.T) {
	privateURL := "https://private-signer.example.com/v1/sign"
	for _, responder := range []rpcDoerFunc{
		func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("Post %s: failed", privateURL) },
		func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusBadGateway, privateURL), nil
		},
		func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"`+privateURL+`":true}`), nil
		},
	} {
		client := &publicEmulatorClient{origin: "https://private-signer.example.com", hc: responder}
		_, err := client.signPinnedOnchain(context.Background(), "cHNidA==")
		if err == nil || strings.Contains(err.Error(), "private-signer") || strings.Contains(err.Error(), "/v1/") {
			t.Fatal("signer failure must not disclose a URL or upstream body")
		}
	}
}
