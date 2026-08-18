package deployment

import (
	"strings"
	"testing"
)

func TestConfigValidatesRegtestAndMutinynet(t *testing.T) {
	mutiny := func(origin, rp string) Config {
		return Config{
			ClientOrigin: origin, RPID: rp, Network: NetworkMutinynet,
			OperationalCSVBlocks: 4032, SavingsCSVBlocks: 288,
		}
	}
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{name: "default regtest", config: Default()},
		{name: "mutinynet", config: mutiny("https://vault.example.com", "vault.example.com")},
		{name: "mutinynet needs https", config: mutiny("http://vault.example.com", "vault.example.com"), wantErr: "https"},
		{name: "origin rp mismatch", config: mutiny("https://vault.example.com", "example.com"), wantErr: "equal"},
		{name: "path rejected", config: mutiny("https://vault.example.com/app", "vault.example.com"), wantErr: "only scheme"},
		{name: "trailing slash rejected", config: mutiny("https://vault.example.com/", "vault.example.com"), wantErr: "only scheme"},
		{name: "uppercase origin rejected", config: mutiny("https://Vault.Example.com", "vault.example.com"), wantErr: "canonical"},
		{name: "uppercase rp rejected", config: mutiny("https://vault.example.com", "Vault.Example.com"), wantErr: "canonical"},
		{name: "trailing dot rp rejected", config: mutiny("https://vault.example.com", "vault.example.com."), wantErr: "canonical"},
		{name: "default port rejected", config: mutiny("https://vault.example.com:443", "vault.example.com"), wantErr: "default port"},
		{name: "empty port rejected", config: mutiny("https://vault.example.com:", "vault.example.com"), wantErr: "empty"},
		{name: "zero padded port rejected", config: mutiny("https://vault.example.com:0443", "vault.example.com"), wantErr: "canonical decimal"},
		{name: "unicode hostname rejected", config: mutiny("https://v\u00e4ult.example.com", "v\u00e4ult.example.com"), wantErr: "ASCII"},
		{name: "mainnet rejected", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: "mainnet", OperationalCSVBlocks: 4032, SavingsCSVBlocks: 288}, wantErr: "unsupported"},
		{name: "mutinynet delays explicit", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet}, wantErr: "CSV"},
		{name: "device delay must exceed hardware", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet, OperationalCSVBlocks: 288, SavingsCSVBlocks: 288}, wantErr: "exceed"},
		{name: "inverted race rejected", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet, OperationalCSVBlocks: 6, SavingsCSVBlocks: 144}, wantErr: "exceed"},
		{name: "aligned mutinynet clocks", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet, OperationalCSVBlocks: 144, SavingsCSVBlocks: 6}},
		{name: "maximum encodable delay", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet, OperationalCSVBlocks: 65535, SavingsCSVBlocks: 65534}},
		{name: "sixteen bit overflow rejected", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet, OperationalCSVBlocks: 288, SavingsCSVBlocks: 65536}, wantErr: "65535"},
		{name: "time unit bit rejected", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet, OperationalCSVBlocks: 288, SavingsCSVBlocks: 1 << 22}, wantErr: "65535"},
		{name: "disable bit rejected", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: NetworkMutinynet, OperationalCSVBlocks: 288, SavingsCSVBlocks: 1 << 31}, wantErr: "65535"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Validate() = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			height, checkpoint, err := test.config.BitcoinCheckpoint()
			if err != nil {
				t.Fatal(err)
			}
			if test.config.Network == NetworkMutinynet && (height != 1 || checkpoint != MutinynetCheckpoint1) {
				t.Fatalf("mutinynet checkpoint = %d:%s", height, checkpoint)
			}
		})
	}
}

func TestPartialConfigDoesNotInheritSecurityIdentity(t *testing.T) {
	partial := Config{Network: NetworkMutinynet}.WithDefaults()
	if partial.ClientOrigin != "" || partial.RPID != "" {
		t.Fatalf("partial config inherited identity: %+v", partial)
	}
	if err := partial.Validate(); err == nil {
		t.Fatal("partial config accepted")
	}
}
