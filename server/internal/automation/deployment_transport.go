package automation

import (
	"net/http"
	"sync/atomic"
)

// A rejection only proves the current request did not commit. An earlier
// accepted POST/PUT/PATCH in the same workflow may already have changed a
// remote target, so restarting the whole deployment would be unsafe.
type deploymentTransport struct {
	base     http.RoundTripper
	accepted atomic.Int64
}

func (t *deploymentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if err == nil && response.StatusCode < 400 && req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != http.MethodOptions {
		t.accepted.Add(1)
	}
	return response, err
}
func observeDeploymentClient(client *http.Client) (*http.Client, *deploymentTransport) {
	copy := *client
	base := copy.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	observer := &deploymentTransport{base: base}
	copy.Transport = observer
	return &copy, observer
}
