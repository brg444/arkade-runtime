package deployment

import "fmt"

const (
	NetworkMainnet = "mainnet"

	// BitcoinGenesisHash is the Bitcoin genesis block. Mainnet deployments pin
	// this as the chain identity instead of a custom-signet checkpoint.
	BitcoinGenesisHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	MainnetArkadeCosignerOrigin  = "https://mainnet-signer.invalid"
	MainnetArkadeCosignerPubHex  = "0239c196415da47b26456a101daaa12ba9e445bfe153197f1e2b750bf40e52092e"
	MainnetArkadeCosignerVersion = "v0.0.7"

	MainnetArkIndexerOrigin = "https://arkade.computer"
	MainnetEsploraOrigin    = "https://mempool.space/api"

	// MainnetVtxoTreeExpirySeconds matches the frozen boarding delay. The
	// Mutinynet release independently pinned Batch Output expiry to the same
	// value as boarding exit; mainnet follows that contract.
	MainnetVtxoTreeExpirySeconds = uint32(7776256)

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
			EmulatorOrigin:          MainnetArkadeCosignerOrigin,
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
