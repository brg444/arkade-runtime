package authorizer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/brg444/arkade-runtime/internal/application"
)

func lnurlRegistrar(origin, tokenFile string) (application.LNURLRegistrar, error) {
	if origin == "" && tokenFile == "" {
		return nil, nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) {
		return nil, fmt.Errorf("Lightning receiving bridge requires HTTPS or loopback HTTP origin")
	}
	stat, err := os.Lstat(tokenFile)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 || stat.Size() > 128 {
		return nil, fmt.Errorf("Lightning receiving bridge requires a private regular token file")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read Lightning receiving bridge token")
	}
	token := strings.TrimSpace(string(raw))
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("invalid Lightning receiving bridge token")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, action string, binding application.LNURLBinding, name string) (json.RawMessage, error) {
		body, err := json.Marshal(struct {
			Name    string                   `json:"name,omitempty"`
			Action  string                   `json:"action"`
			Binding application.LNURLBinding `json:"binding"`
		}{name, action, binding})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/v1/vaulted/registration", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Lightning receiving service unavailable")
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || response.StatusCode != http.StatusOK || len(payload) > 16384 || !json.Valid(payload) {
			return nil, fmt.Errorf("Lightning receiving registration unavailable")
		}
		return json.RawMessage(payload), nil
	}, nil
}
