package v2rayxhttp

import (
	"net/http"
	"strings"
	"testing"
)

func TestApplyDefaultXPaddingAddsRefererQueryPadding(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://apple.com/test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	applyDefaultXPadding(req)

	referer := req.Header.Get("Referer")
	if referer == "" {
		t.Fatal("expected Referer header to be set")
	}
	if got := req.Header.Get("Content-Type"); got != "" {
		t.Fatalf("expected Content-Type untouched, got %q", got)
	}
	if want := "x_padding="; !strings.Contains(referer, want) {
		t.Fatalf("expected Referer to contain %q, got %q", want, referer)
	}
	padding := req.Header.Get("Referer")
	if len(padding) <= len("https://apple.com/test/?x_padding=") {
		t.Fatalf("expected Referer padding payload, got %q", referer)
	}
}
