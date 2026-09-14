package authorizer

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/btcsuite/btcd/btcec/v2"
)

type forbiddenStartupTransport struct{ calls atomic.Int32 }

func (t *forbiddenStartupTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errors.New("unexpected startup HTTP request")
}

func TestRetainedDescriptorIdentityNeedsNoRemoteSigner(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	t.Setenv("VAULT_ARKADE_COSIGNER_ORIGIN", "https://retired.invalid")
	transport := &forbiddenStartupTransport{}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			dir := t.TempDir()
			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			defer key.Zero()
			keyPath, tokenPath := filepath.Join(dir, "guardian.key"), filepath.Join(dir, "invite")
			if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key.Serialize())), 0600); err != nil {
				t.Fatal(err)
			}
			token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
			if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			origin, rp := "https://vault.example.com", "vault.example.com"
			if network == deployment.NetworkMainnet {
				origin, rp = deployment.MainnetWalletOrigin, deployment.MainnetWalletRPID
			}
			cfg := Config{Deployment: deployment.Config{Network: network, ClientOrigin: origin, RPID: rp}, DatabasePath: filepath.Join(dir, "policy.sqlite"), PolicySequencePath: filepath.Join(dir, "sequence"), VaultCosignerKeyFile: keyPath, EnrollmentTokenFile: tokenPath, StorageIsolation: "independent-authorities", EdgeRateLimit: "shared-durable", MainnetAcknowledged: "fresh-state-v1"}
			runtime, err := openWithTestResolver(t, t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			pins, err := deployment.IdentityFor(network)
			if err != nil {
				t.Fatal(err)
			}
			expectedOrigin := pins.EmulatorOrigin
			if network == deployment.NetworkMainnet {
				expectedOrigin = deployment.MainnetSignerIdentity
			}
			service := runtime.service
			if hex.EncodeToString(service.ArkadeCosignerPub.SerializeCompressed()) != pins.EmulatorPubHex || service.ArkadeCosignerVersion != pins.EmulatorVersion || service.ArkadeCosignerOrigin != expectedOrigin {
				t.Fatal("retained enrollment identity bytes changed")
			}
			if transport.calls.Load() != 0 {
				t.Fatal("retired signer contacted during startup")
			}
		})
	}
}
