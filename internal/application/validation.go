package application

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func requireTxid(txid string) error {
	if len(txid) != 64 || txid != strings.ToLower(txid) {
		return fmt.Errorf("txid")
	}
	raw, err := hex.DecodeString(txid)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("txid")
	}
	return nil
}
