package application

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/policy"
)

// Opt-in local browser harness. It uses an ephemeral ledger and keys and binds
// loopback only; it is absent from production binaries and normal test runs.
func TestLightBrowserHarness(t *testing.T) {
	addr := os.Getenv("VAULT_LIGHT_BROWSER_ADDR")
	if addr == "" {
		t.Skip("local browser harness not requested")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("browser harness requires loopback")
	}
	origin := os.Getenv("VAULT_LIGHT_BROWSER_ORIGIN")
	if !strings.HasPrefix(origin, "https://localhost:") {
		t.Fatal("browser harness requires HTTPS localhost origin")
	}
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "light-browser.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	svc := enrollService(t, ledger)
	svc.LightEnabled = true
	svc.OpenEnrollment = true
	svc.Deployment.ClientOrigin = origin
	svc.Deployment.RPID = "localhost"
	svc.ArkResolver = stubArkResolver{signer: mustDecode(t, "02301078808e4f7bc0dadfe29e34b1df8eaf0108ef06b1722274075ebc107a127a")}
	if mode := os.Getenv("VAULT_LIGHT_BROWSER_LIVE"); mode != "" {
		if mode != "mutinynet" {
			t.Fatal("funded browser harness supports only Mutinynet")
		}
		svc.ArkResolver, err = DialArkResolver(context.Background(), "mutinynet")
		if err != nil {
			t.Fatal(err)
		}
	}
	server := NewServer(addr, testAuthorizer(svc))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	t.Log("Light browser harness ready")
	select {
	case err := <-stopped:
		if err != nil && err != http.ErrServerClosed {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Minute):
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
}
