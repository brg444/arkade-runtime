package application

import (
	"fmt"
	"io"
	"net/url"
	"strings"
)

func CanonicalHTTPSOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("HTTP endpoint requires a canonical https origin")
	}
	if u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("HTTP endpoint URL must be an origin without credentials, path, query, or fragment")
	}
	// The release pin uses the default HTTPS port and a canonical DNS name.
	// Reject empty, explicit, IPv6, and otherwise browser-normalized authority
	// forms instead of accepting two textual identities for the same endpoint.
	if u.Host != u.Hostname() || strings.HasSuffix(u.Hostname(), ".") || strings.IndexFunc(u.Hostname(), func(r rune) bool { return r > 127 }) >= 0 {
		return "", fmt.Errorf("HTTP endpoint origin must use a canonical ASCII hostname and implicit HTTPS port")
	}
	canonical := "https://" + strings.ToLower(u.Host)
	if raw != canonical {
		return "", fmt.Errorf("HTTP endpoint origin must be canonical lowercase and omit the default port")
	}
	return canonical, nil
}

func readBoundedResponse(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("invalid response bound")
	}
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("HTTP endpoint response too large")
	}
	return raw, nil
}
