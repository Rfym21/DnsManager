package automation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptimizationSourceProtocolFamiliesAndLines(t *testing.T) {
	for _, kind := range []string{"wetest", "hostmonit", "xingpingcn"} {
		t.Run(kind, func(t *testing.T) {
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "xingpingcn" {
					if r.Method != "GET" {
						t.Error("wrong method")
					}
					w.Write([]byte(`{"Cf":{"result":{"dianxin":["192.0.2.3"],"liantong":["192.0.2.4"],"yidong":["192.0.2.5"],"default":["192.0.2.6"]}}}`))
					return
				}
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				if r.Method != "POST" || body["key"] != "fixture-secret" || body["type"] != "v6" || !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
					t.Error("wrong source protocol")
				}
				if kind == "wetest" && r.URL.Path != "/get_edgeone_ip" {
					t.Error("wrong CDN path")
				}
				if kind == "hostmonit" && r.URL.Path != "/get_optimization_ip" {
					t.Error("wrong path")
				}
				w.Write([]byte(`{"code":200,"info":{"DEF":["2001:db8::1","2001:db8::1","192.0.2.1"],"CT":[{"ip":"2001:db8::2"}]}}`))
			}))
			defer remote.Close()
			d := OptimizationData{SourceProvider: kind, SourceConfig: map[string]string{"api_base": remote.URL, "key": "fixture-secret", "cdn_type": "4"}}
			family := "ipv6"
			if kind == "xingpingcn" {
				d.SourceURL = remote.URL
				family = "ipv4"
			}
			groups, err := fetchOptimizationSource(context.Background(), remote.Client(), d, family)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "xingpingcn" {
				if len(groups) != 3 || len(groups["DEF"]) != 0 {
					t.Fatal("commented default restored", groups)
				}
			} else if len(groups["DEF"]) != 1 || len(groups["CT"]) != 1 {
				t.Fatal("family filtering/dedup failed", groups)
			}
		})
	}
}

func TestOptimizationSourceRejectsInvalidAndEmptyResponses(t *testing.T) {
	for _, body := range []string{`{"code":401,"info":"fixture-secret"}`, `{"code":200,"info":{"DEF":["bad"]}}`, `{"code":200}`, `bad`} {
		remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, err := fetchOptimizationSource(context.Background(), remote.Client(), OptimizationData{SourceProvider: "hostmonit", SourceConfig: map[string]string{"api_base": remote.URL, "key": "fixture-secret"}}, "ipv4")
		remote.Close()
		if err == nil || strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("empty/error source accepted or leaked", err)
		}
	}
}
