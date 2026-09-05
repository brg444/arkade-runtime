package program

import "testing"

func TestPinsForMutinynetMatchesLegacyConstants(t *testing.T) {
	pins, err := PinsFor(NetworkMutinynet)
	if err != nil {
		t.Fatal(err)
	}
	if pins.PolicyExitDelay != VaultPolicyV1ExitDelay || pins.BoardExitDelay != VaultBoardV1ExitDelay {
		t.Fatalf("%+v", pins)
	}
	if err := ValidateVaultPolicyV1ExitDelayFor(NetworkMutinynet, pins.PolicyExitDelay, VaultPolicyV1ExitDelayUnit); err != nil {
		t.Fatal(err)
	}
	if err := ValidateVaultBoardV1ExitDelayFor(NetworkMutinynet, pins.BoardExitDelay, VaultBoardV1ExitDelayUnit); err != nil {
		t.Fatal(err)
	}
}

func TestPinsForMainnetMatchesOperatorContract(t *testing.T) {
	pins, err := PinsFor(NetworkMainnet)
	if err != nil {
		t.Fatal(err)
	}
	if pins.PolicyExitDelay != 605184 || pins.BoardExitDelay != 7776256 || pins.ArkdMinExitDelay != 605184 {
		t.Fatalf("%+v", pins)
	}
	if pins.AbsoluteFeeCeiling != 20_000 || pins.FeerateCeilingSatPerV != 25 {
		t.Fatalf("alpha mainnet fee ceilings = %+v", pins)
	}
	if pins.PolicyExitDelay%VaultPolicyV1BIP68SecondsMod != 0 || pins.BoardExitDelay%VaultPolicyV1BIP68SecondsMod != 0 {
		t.Fatal("BIP68")
	}
	if err := ValidateVaultPolicyV1ExitDelayFor(NetworkMainnet, 4608, "seconds"); err == nil {
		t.Fatal("mutinynet hatch accepted on mainnet")
	}
	if err := ValidateVaultBoardV1ExitDelayFor(NetworkMainnet, 604672, "seconds"); err == nil {
		t.Fatal("mutinynet boarding delay accepted on mainnet")
	}
	if _, err := PinsFor("regtest"); err == nil {
		t.Fatal("regtest accepted")
	}
}
