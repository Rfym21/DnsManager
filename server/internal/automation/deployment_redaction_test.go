package automation

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	deployprovider "github.com/dns-manager/dnsmgr/server/internal/providers/deploy"
)

func TestDeploymentErrorEchoRedaction(t *testing.T) {
	private := "-----BEGIN PRIVATE KEY-----\nsynthetic-long-private-material\n-----END PRIVATE KEY-----"
	escaped, _ := json.Marshal(private)
	info := deployprovider.Info{"results": []any{map[string]any{"error": "fixture-password " + private + " " + base64.StdEncoding.EncodeToString([]byte(private))}, map[string]any{"error": string(escaped)}}, "message": "fixture-pfx-pass"}
	clean := redactDeploymentInfo(info, map[string]string{"password": "fixture-password"}, map[string]string{"pfx_pass": "fixture-pfx-pass"}, "", private)
	raw, _ := json.Marshal(clean)
	for _, forbidden := range []string{"fixture-password", "fixture-pfx-pass", "synthetic-long-private-material", base64.StdEncoding.EncodeToString([]byte(private))} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("deployment error echoed secret material")
		}
	}
	if safeLogData(nil) != nil {
		t.Fatal("empty provider log changed representation")
	}
}
