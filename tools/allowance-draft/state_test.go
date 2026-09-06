package allowancedraft

import (
	"bytes"
	"testing"
)

func FuzzStateEncoding(f *testing.F) {
	for _, s := range []State{{0, 0}, {10000, 5}, {MaxBudget, MaxSequence}} {
		raw, err := s.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte("VA00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := DecodeState(raw)
		if err != nil {
			return
		}
		again, err := s.Encode()
		check(t, err)
		if !bytes.Equal(raw, again) {
			t.Fatal("accepted noncanonical state")
		}
	})
}

func TestCompileBounds(t *testing.T) {
	base := newFixture(t).p
	for _, tc := range []struct {
		name   string
		mutate func(*Parameters)
	}{
		{"empty identity", func(p *Parameters) { p.ControllerID.Txid = [32]byte{} }},
		{"negative budget", func(p *Parameters) { p.Budget = -1 }},
		{"budget too large", func(p *Parameters) { p.Budget = MaxBudget + 1 }},
		{"recipient above budget", func(p *Parameters) { p.RecipientCap = p.Budget + 1 }},
		{"negative fee", func(p *Parameters) { p.FeeCap = -1 }},
		{"fee too large", func(p *Parameters) { p.FeeCap = 100001 }},
		{"zero renewal window", func(p *Parameters) { p.RenewalWindow = 0 }},
		{"renewal window too long", func(p *Parameters) { p.RenewalWindow = 30*86400 + 1 }},
		{"invalid delegate", func(p *Parameters) { p.DelegatePubkey = make([]byte, 33) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			if _, err := Compile(p); err == nil {
				t.Fatal("invalid parameters compiled")
			}
		})
	}
}
