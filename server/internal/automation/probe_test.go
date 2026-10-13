package automation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHTTPProbeSeparatesStatusAndBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("healthy")) }))
	defer server.Close()
	result := Probe(context.Background(), ProbeSpec{Protocol: "http", Target: server.URL, ExpectedBody: "healthy"})
	if !result.Healthy {
		t.Fatal(result)
	}
	result = Probe(context.Background(), ProbeSpec{Protocol: "http", Target: server.URL, ExpectedBody: "missing"})
	if result.Healthy || result.Error == "" {
		t.Fatal("missing expected body must fail", result)
	}
}

func TestHTTPProbePinsIPAndPreservesHost(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Host; w.Write([]byte("healthy")) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	target := "http://probe.example.invalid:" + u.Port() + "/"
	result := Probe(context.Background(), ProbeSpec{Protocol: "http", Target: target, ConnectIP: "127.0.0.1", TimeoutSeconds: 2})
	if !result.Healthy {
		t.Fatal(result)
	}
	if host := <-seen; host != "probe.example.invalid:"+u.Port() {
		t.Fatal("lost original Host", host)
	}
}
