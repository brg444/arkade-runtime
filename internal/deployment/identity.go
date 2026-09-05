package deployment

import "fmt"

const (
	NetworkMainnet = "mainnet"

	// MainnetSignerIdentity is public descriptor metadata, never a transport URL.
	MainnetSignerIdentity = "urn:vaulted:mainnet-signer:v1"

	// BitcoinGenesisHash is the Bitcoin genesis block. Mainnet deployments pin
	// this as the chain identity instead of a custom-signet checkpoint.
	BitcoinGenesisHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	// Mainnet wallet WebAuthn origins. Parent-domain getvaulted.xyz and the
	// Guardian ingress are not valid relying parties for this release.
	MainnetWalletOrigin = "https://app.getvaulted.xyz"
	MainnetWalletRPID   = "app.getvaulted.xyz"
	MainnetRCOrigin     = "https://rc.getvaulted.xyz"
	MainnetRCRPID       = "rc.getvaulted.xyz"

	MainnetArkadeCosignerPubHex  = "0239c196415da47b26456a101daaa12ba9e445bfe153197f1e2b750bf40e52092e"
	MainnetArkadeCosignerVersion = "v0.0.7"

	MainnetArkIndexerOrigin = "https://arkade.computer"
	MainnetEsploraOrigin    = "https://mempool.space/api"

	// MainnetVtxoTreeExpirySeconds pins Batch Output expiry independently of
	// the boarding recovery delay. The public mainnet Operator emitted 2592256
	// in BatchStarted be8cd65e-6466-44d6-8691-6ea9360fa23c on 2026-09-05.
	MainnetVtxoTreeExpirySeconds = uint32(2592256)

	MainnetOperatorSignerPubHex    = "038202bebddeb1f7442803897a85eaf3ce9254d07df0172fc3725ab5f0d097779c"
	MainnetCheckpointForfeitPubHex = "03b43a8363118c084a04d4f6a50ebfa58e81957f8cceceb2aee0ab64c9fd2d9977"
	MainnetCheckpointTapscriptHex  = "039e0440b27520b43a8363118c084a04d4f6a50ebfa58e81957f8cceceb2aee0ab64c9fd2d9977ac"
	MainnetCheckpointDelaySeconds  = uint32(605184)
)

// Identity is one frozen network deployment. Program delays live in package
// program; this type owns Operator, Emulator, indexer, Esplora, and chain pins.
type Identity struct {
	Network                 string
	OperatorGetInfoNetwork  string
	OperatorOrigin          string
	EsploraOrigin           string
	EmulatorOrigin          string
	EmulatorPubHex          string
	EmulatorVersion         string
	OperatorSignerPubHex    string
	CheckpointForfeitPubHex string
	CheckpointTapscriptHex  string
	CheckpointDelaySeconds  uint32
	CheckpointHeight        int64
	CheckpointHash          string
	VtxoTreeExpirySeconds   uint32
}

// IdentityFor returns the release-pinned identity for a product network.
func IdentityFor(network string) (Identity, error) {
	switch network {
	case NetworkMutinynet:
		return Identity{
			Network:                 NetworkMutinynet,
			OperatorGetInfoNetwork:  NetworkMutinynet,
			OperatorOrigin:          MutinynetArkIndexerOrigin,
			EsploraOrigin:           MutinynetEsploraOrigin,
			EmulatorOrigin:          MutinynetArkadeCosignerOrigin,
			EmulatorPubHex:          MutinynetArkadeCosignerPubHex,
			EmulatorVersion:         MutinynetArkadeCosignerVersion,
			OperatorSignerPubHex:    MutinynetOperatorSignerPubHex,
			CheckpointForfeitPubHex: MutinynetCheckpointForfeitPubHex,
			CheckpointTapscriptHex:  MutinynetCheckpointTapscriptHex,
			CheckpointDelaySeconds:  MutinynetCheckpointDelaySeconds,
			CheckpointHeight:        1,
			CheckpointHash:          MutinynetCheckpoint1,
			VtxoTreeExpirySeconds:   MutinynetVtxoTreeExpirySeconds,
		}, nil
	case NetworkMainnet:
		return Identity{
			Network:                 NetworkMainnet,
			OperatorGetInfoNetwork:  "bitcoin",
			OperatorOrigin:          MainnetArkIndexerOrigin,
			EsploraOrigin:           MainnetEsploraOrigin,
			EmulatorPubHex:          MainnetArkadeCosignerPubHex,
			EmulatorVersion:         MainnetArkadeCosignerVersion,
			OperatorSignerPubHex:    MainnetOperatorSignerPubHex,
			CheckpointForfeitPubHex: MainnetCheckpointForfeitPubHex,
			CheckpointTapscriptHex:  MainnetCheckpointTapscriptHex,
			CheckpointDelaySeconds:  MainnetCheckpointDelaySeconds,
			CheckpointHeight:        0,
			CheckpointHash:          BitcoinGenesisHash,
			VtxoTreeExpirySeconds:   MainnetVtxoTreeExpirySeconds,
		}, nil
	default:
		return Identity{}, fmt.Errorf("unsupported network %q", network)
	}
}
