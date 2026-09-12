package application

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func jsonResponse(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestHTTPOriginAndResponseBounds(t *testing.T) {
	for _, origin := range []string{"http://operator.example.com", "https://Operator.example.com", "https://operator.example.com/", "https://operator.example.com:443", "https://operator.example.com:", "https://operator.example.com:08443", "https://operator.example.com.", "https://user:secret@operator.example.com", "https://operator.example.com?q=secret", "https://operator.example.com#secret"} {
		if _, err := CanonicalHTTPSOrigin(origin); err == nil {
			t.Fatalf("noncanonical origin accepted: %q", origin)
		}
	}
	if got, err := CanonicalHTTPSOrigin("https://operator.example.com"); err != nil || got != "https://operator.example.com" {
		t.Fatal("canonical origin rejected", err)
	}
	if _, err := readBoundedResponse(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized response accepted")
	}
	if got, err := readBoundedResponse(strings.NewReader("1234"), 4); err != nil || string(got) != "1234" {
		t.Fatal("exact response limit rejected", err)
	}
	if _, err := readBoundedResponse(strings.NewReader(""), 0); err == nil {
		t.Fatal("zero response limit accepted")
	}
}
