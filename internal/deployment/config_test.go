package deployment

import (
	"strings"
	"testing"
)

func TestConfigValidatesOnlyMutinynetCandidate(t *testing.T) {
	mutiny := func(origin, rp string) Config {
		return Config{ClientOrigin: origin, RPID: rp, Network: NetworkMutinynet}
	}
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{name: "regtest rejected", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: "regtest"}, wantErr: "unsupported"},
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
		{name: "mainnet rejected until release pins exist", config: Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: "mainnet"}, wantErr: "unsupported"},
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
	partial := Config{Network: NetworkMutinynet}
	if err := partial.Validate(); err == nil {
		t.Fatal("partial config accepted")
	}
}
