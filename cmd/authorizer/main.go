package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/brg444/arkade-vault-server/internal/authorizer"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	httpapi "github.com/brg444/arkade-vault-server/internal/iface/http"
)

func main() {
	var (
		addr      = flag.String("addr", envOr("VAULT_AUTHORIZER_ADDR", "127.0.0.1:8788"), "internal authorizer listen address")
		dbPath    = flag.String("db", os.Getenv("VAULT_DB_PATH"), "absolute authoritative SQLite path")
		sequence  = flag.String("policy-sequence", os.Getenv("VAULT_POLICY_SEQUENCE_PATH"), "absolute external policy-sequence path")
		keyFile   = flag.String("vault-cosigner-key-file", os.Getenv("VAULT_VAULT_COSIGNER_KEY_FILE"), "file containing the VaultCosigner private scalar")
		tokenFile = flag.String("enrollment-token-file", os.Getenv("VAULT_ENROLLMENT_TOKEN_FILE"), "offline-provisioned one-time enrollment token file")
		origin    = flag.String("client-origin", os.Getenv("VAULT_CLIENT_ORIGIN"), "exact HTTPS signing-client origin")
		rpID      = flag.String("rp-id", os.Getenv("VAULT_RP_ID"), "exact WebAuthn relying-party ID")
		network   = flag.String("network", envOr("VAULT_NETWORK", deployment.NetworkMutinynet), "must be mutinynet")
	)
	flag.Parse()

	cfg := authorizer.Config{
		Deployment:           deployment.Config{ClientOrigin: *origin, RPID: *rpID, Network: *network},
		DatabasePath:         *dbPath,
		PolicySequencePath:   *sequence,
		VaultCosignerKeyFile: *keyFile,
		EnrollmentTokenFile:  *tokenFile,
	}
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 40*time.Second)
	runtime, err := authorizer.Open(startupCtx, cfg)
	startupCancel()
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close()
	if err := clearGatewaySecretEnv(); err != nil {
		_ = runtime.Close()
		log.Fatalf("clear gateway secret environment: %v", err)
	}

	server := httpapi.NewServer(*addr, runtime.Handler())
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()
	log.Printf("Mutinynet software authorizer listening internally on %s; key and ledger share this process", *addr)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	case <-signalCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("authorizer shutdown: %v", err)
		}
	}
}

func clearGatewaySecretEnv() error {
	return os.Unsetenv("VAULT_GATEWAY_SECRET")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
