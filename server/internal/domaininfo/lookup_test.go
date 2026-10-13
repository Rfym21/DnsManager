package domaininfo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistryBootstrapAndRegistrableDomain(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bootstrap":
			json.NewEncoder(w).Encode(map[string]any{"services": [][][]string{{{"com"}, {server.URL}}}})
		case "/domain/example.com":
			json.NewEncoder(w).Encode(map[string]any{"events": []map[string]string{{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}, {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	l := Lookup{BootstrapURL: server.URL + "/bootstrap"}
	d, err := l.Resolve(context.Background(), "www.example.com")
	if err != nil || d.Domain != "example.com" || d.RegisteredAt == nil || d.ExpiresAt == nil || d.ExpiresAt.Year() != 2030 {
		t.Fatalf("%+v %v", d, err)
	}
}
func TestWhoisFallbackAndUnknownExpiration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	l := Lookup{BootstrapURL: server.URL, Whois: func(_ context.Context, host, query string) (string, error) {
		if host == "whois.iana.org" {
			return "whois: whois.example.org\n", nil
		}
		return "Creation Date: 2020-02-01T00:00:00Z\nRegistry Expiry Date: 2030-02-01T00:00:00Z\n", nil
	}}
	d, err := l.Resolve(context.Background(), "example.com")
	if err != nil || d.Source != "whois" || d.ExpiresAt == nil {
		t.Fatalf("%+v %v", d, err)
	}
	l.Whois = func(context.Context, string, string) (string, error) { return "", errors.New("unavailable") }
	d, err = l.Resolve(context.Background(), "example.com")
	if err == nil || d.ExpiresAt != nil {
		t.Fatalf("unknown expiration must stay unknown: %+v %v", d, err)
	}
}
