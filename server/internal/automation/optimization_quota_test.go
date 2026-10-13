package automation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptimizationQuotaProtocolAndSecretSafeFailures(t *testing.T) {
	for _, kind := range []string{"wetest", "hostmonit"} {
		t.Run(kind, func(t *testing.T) {
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/get_license" || r.URL.Query().Get("license") != "fixture-quota-secret" {
					t.Error("quota protocol mismatch")
				}
				w.Write([]byte(`{"code":200,"count":"42"}`))
			}))
			defer remote.Close()
			result, e := fetchOptimizationQuota(context.Background(), remote.Client(), OptimizationData{SourceProvider: kind, SourceConfig: map[string]string{"api_base": remote.URL, "key": "fixture-quota-secret"}})
			if e != nil || result["remaining"] != int64(42) {
				t.Fatal(result, e)
			}
		})
	}
	for _, body := range []string{`{"code":403,"info":"fixture-quota-secret"}`, `{"code":200,"count":-1}`, `{"code":200}`} {
		remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, e := fetchOptimizationQuota(context.Background(), remote.Client(), OptimizationData{SourceProvider: "wetest", SourceConfig: map[string]string{"api_base": remote.URL, "key": "fixture-quota-secret"}})
		remote.Close()
		if e == nil || strings.Contains(e.Error(), "fixture-quota-secret") {
			t.Fatal("invalid quota accepted or secret echoed", e)
		}
	}
	result, e := fetchOptimizationQuota(context.Background(), nil, OptimizationData{SourceProvider: "xingpingcn"})
	if e != nil || result["unlimited"] != true {
		t.Fatal(result, e)
	}
}
