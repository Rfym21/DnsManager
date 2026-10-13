package automation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeploymentRejectionDoesNotErasePriorAcceptedRequest(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deny" {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer remote.Close()
	client, observer := observeDeploymentClient(remote.Client())
	for _, step := range []struct {
		method, path string
		accepted     int64
	}{{"GET", "/read", 0}, {"POST", "/deny", 0}, {"POST", "/upload", 1}, {"PUT", "/deny", 1}} {
		req, _ := http.NewRequestWithContext(context.Background(), step.method, remote.URL+step.path, nil)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if observer.accepted.Load() != step.accepted {
			t.Fatal("accepted remote write evidence lost")
		}
	}
}
