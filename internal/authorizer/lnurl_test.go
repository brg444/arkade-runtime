package authorizer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/application"
)

func TestLNURLBridgeBindsRequestAndRejectsBadResponses(t *testing.T) {
	token := strings.Repeat("ab", 32)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	mode := "ok"
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/vaulted/registration" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("bridge request changed")
		}
		var body struct {
			Action  string                   `json:"action"`
			Binding application.LNURLBinding `json:"binding"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Action != "register" || body.Binding.VaultID != "enrolled-vault" {
			t.Error("bridge binding changed")
		}
		switch mode {
		case "redirect":
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "large":
			_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("x", 16384) + `"}`))
		case "invalid":
			_, _ = w.Write([]byte("not JSON"))
		case "denied":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte(`{"active":true}`))
		}
	}))
	defer server.Close()
	registrar, err := lnurlRegistrar(server.URL, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"ok", "redirect", "large", "invalid", "denied"} {
		mode = value
		before := calls
		result, err := registrar(context.Background(), "register", application.LNURLBinding{VaultID: "enrolled-vault"})
		if (err == nil) != (mode == "ok") {
			t.Fatalf("%s: result=%s err=%v", mode, result, err)
		}
		if calls != before+1 {
			t.Fatal("redirect followed")
		}
	}
}

func TestLNURLBridgeRequiresPrivateFileAndFixedOrigin(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if registrar, err := lnurlRegistrar("", ""); err != nil || registrar != nil {
		t.Fatal("disabled bridge")
	}
	for _, origin := range []string{"http://example.com", "https://user@example.com", "https://example.com/path", "https://example.com?token=x", "https://example.com#x"} {
		if _, err := lnurlRegistrar(origin, file); err == nil {
			t.Fatalf("accepted %s", origin)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := lnurlRegistrar("https://ln.getvaulted.xyz", link); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := lnurlRegistrar("https://ln.getvaulted.xyz", file); err == nil {
		t.Fatal("accepted public token")
	}
}
