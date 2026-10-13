package redaction

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNestedCredentialsAndKeyParameters(t *testing.T) {
	raw := json.RawMessage(`{"key_type":"ecdsa","key_size":256,"config":{"url":"https://example.invalid/hook/token","headers":"Authorization: Bearer hidden","proxy_url":"socks5://u:password@localhost"},"steps":[{"detail":{"private_key":"PEM","email":"visible"}}]}`)
	out := string(JSON(raw))
	for _, secret := range []string{"/hook/token", "Bearer hidden", "u:password", "PEM"} {
		if strings.Contains(out, secret) {
			t.Fatal("credential escaped", secret)
		}
	}
	if !strings.Contains(out, "ecdsa") || !strings.Contains(out, "256") || !strings.Contains(out, "visible") {
		t.Fatal("public parameters removed", out)
	}
}
