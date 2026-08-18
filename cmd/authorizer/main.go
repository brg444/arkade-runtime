package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/brg444/arkade-vault-server/internal/authorizer"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	httpapi "github.com/brg444/arkade-vault-server/internal/iface/http"
)

func main() {
	opDefault, err := envUint32("VAULT_OPERATIONAL_CSV_BLOCKS")
	if err != nil {
		log.Fatal(err)
	}
	savingsDefault, err := envUint32("VAULT_SAVINGS_CSV_BLOCKS")
	if err != nil {
		log.Fatal(err)
	}

	var (
		addr       = flag.String("addr", envOr("VAULT_AUTHORIZER_ADDR", "127.0.0.1:8788"), "internal authorizer listen address")
		dbPath     = flag.String("db", os.Getenv("VAULT_DB_PATH"), "absolute authoritative SQLite path")
		keyFile    = flag.String("vault-cosigner-key-file", os.Getenv("VAULT_VAULT_COSIGNER_KEY_FILE"), "file containing the VaultCosigner private scalar")
		ownerHex   = flag.String("external-owner-wallet", os.Getenv("VAULT_EXTERNAL_OWNER_WALLET_PUB"), "independent compressed ExternalOwnerWallet public key")
		tokenFile  = flag.String("enrollment-token-file", os.Getenv("VAULT_ENROLLMENT_TOKEN_FILE"), "one-time first-enrollment token file")
		esploraURL = flag.String("esplora-url", os.Getenv("VAULT_ESPLORA_URL"), "checkpoint-pinned Mutinynet Esplora base URL")
		origin     = flag.String("client-origin", os.Getenv("VAULT_CLIENT_ORIGIN"), "exact HTTPS signing-client origin")
		rpID       = flag.String("rp-id", os.Getenv("VAULT_RP_ID"), "exact WebAuthn relying-party ID")
		network    = flag.String("network", envOr("VAULT_NETWORK", deployment.NetworkMutinynet), "must be mutinynet")
		opCSV      = flag.Uint64("operational-csv-blocks", uint64(opDefault), "device-only CSV delay in blocks")
		savingsCSV = flag.Uint64("savings-csv-blocks", uint64(savingsDefault), "hardware-only CSV delay in blocks")
		freshOnly  = flag.Bool("fresh-only", !envTruthy("VAULT_ALLOW_LEGACY"), "refuse legacy credential/database files before any backup or migrate")
	)
	flag.Parse()
	if *opCSV > uint64(deployment.MaxCSVBlockDelay) || *savingsCSV > uint64(deployment.MaxCSVBlockDelay) {
		log.Fatalf("CSV block delays must not exceed %d", deployment.MaxCSVBlockDelay)
	}

	cfg := authorizer.Config{
		Deployment: deployment.Config{
			ClientOrigin:         *origin,
			RPID:                 *rpID,
			Network:              *network,
			OperationalCSVBlocks: uint32(*opCSV),
			SavingsCSVBlocks:     uint32(*savingsCSV),
		},
		DatabasePath:              *dbPath,
		VaultCosignerKeyFile:      *keyFile,
		ExternalOwnerWalletPubHex: *ownerHex,
		EnrollmentTokenFile:       *tokenFile,
		MultiTenantEnrollment:     true,
		FreshOnly:                 *freshOnly,
		EsploraURL:                *esploraURL,
	}
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 40*time.Second)
	runtime, err := authorizer.Open(startupCtx, cfg)
	startupCancel()
	if err != nil {
		log.Fatal(err)
	}
	defer runtime.Close()

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

func envUint32(key string) (uint32, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be a uint32", key)
	}
	return uint32(n), nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envTruthy(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
