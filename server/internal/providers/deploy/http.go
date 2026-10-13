package deploy

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type httpProvider struct {
	kind   string
	cfg    map[string]string
	opts   Options
	base   string
	client *http.Client
}

func newHTTP(kind string, cfg map[string]string, opts Options) (*httpProvider, error) {
	u, err := url.Parse(strings.TrimRight(cfg["url"], "/"))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("valid HTTP(S) panel URL is required")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &httpProvider{kind: kind, cfg: cfg, opts: opts, base: u.String(), client: client}, nil
}
func readLimited(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, (16<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 16<<20 {
		return nil, errors.New("provider response exceeds limit")
	}
	return raw, nil
}
func (p *httpProvider) request(ctx context.Context, method, path string, body []byte, headers map[string]string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed: %w", p.kind, err)
	}
	defer resp.Body.Close()
	raw, err := readLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if len(raw) > 0 && decoder.Decode(&value) != nil {
		if resp.StatusCode/100 != 2 {
			return nil, rejectedHTTP(p.kind, resp.StatusCode, "provider request failed")
		}
		return nil, errors.New("provider returned invalid JSON")
	}
	if resp.StatusCode/100 != 2 {
		return nil, rejectedHTTP(p.kind, resp.StatusCode, safeError(value, p.cfg))
	}
	return value, nil
}
func (p *httpProvider) json(ctx context.Context, method, path string, body any, headers map[string]string) (any, error) {
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	return p.request(ctx, method, path, raw, headers)
}
func (p *httpProvider) form(ctx context.Context, path string, values url.Values, headers map[string]string) (any, error) {
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	return p.request(ctx, http.MethodPost, path, []byte(values.Encode()), headers)
}

type filePart struct {
	name, filename string
	data           []byte
}

func (p *httpProvider) multipart(ctx context.Context, method, path string, values map[string]string, files []filePart, headers map[string]string) (any, error) {
	var data bytes.Buffer
	writer := multipart.NewWriter(&data)
	for k, v := range values {
		if err := writer.WriteField(k, v); err != nil {
			return nil, err
		}
	}
	for _, file := range files {
		part, err := writer.CreateFormFile(file.name, file.filename)
		if err != nil {
			return nil, err
		}
		if _, err = part.Write(file.data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = writer.FormDataContentType()
	return p.request(ctx, method, path, data.Bytes(), headers)
}
func safeError(value any, cfg map[string]string) string {
	message := "provider request failed"
	m, ok := value.(map[string]any)
	if ok {
		for _, k := range []string{"msg", "message", "error_description", "error"} {
			if text, ok := m[k].(string); ok && text != "" {
				message = text
				break
			}
		}
		if obj, ok := m["error"].(map[string]any); ok {
			if text, ok := obj["message"].(string); ok {
				message = text
			}
		}
	}
	for _, secret := range cfg {
		if len(secret) > 3 {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	if strings.Contains(message, "-----BEGIN") {
		return "provider request failed"
	}
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}
func obj(value any) map[string]any { m, _ := value.(map[string]any); return m }
func text(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	}
	return ""
}
func truth(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case json.Number:
		n, err := v.Float64()
		return err == nil && n != 0
	case string:
		return v == "true" || v == "1"
	}
	return false
}
func splitLines(value string) []string {
	result := []string{}
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}
func md5hex(value string) string    { hash := md5.Sum([]byte(value)); return hex.EncodeToString(hash[:]) }
func sha256hex(value []byte) string { hash := sha256.Sum256(value); return hex.EncodeToString(hash[:]) }
func parsePair(chain, key string) (*x509.Certificate, []*x509.Certificate, any, error) {
	pair, err := tls.X509KeyPair([]byte(chain), []byte(key))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	certs := []*x509.Certificate{}
	for _, raw := range pair.Certificate {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, nil, err
		}
		certs = append(certs, cert)
	}
	return certs[0], certs[1:], pair.PrivateKey, nil
}
func encodePFX(chain, key, password string) ([]byte, error) {
	leaf, issuers, priv, err := parsePair(chain, key)
	if err != nil {
		return nil, err
	}
	return pkcs12.Modern.Encode(priv, leaf, issuers, password)
}
func splitChain(chain string) (string, string, error) {
	leaf, rest := pem.Decode([]byte(chain))
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return "", "", errors.New("certificate PEM is required")
	}
	return string(pem.EncodeToMemory(leaf)), string(rest), nil
}
func (p *httpProvider) log(ctx context.Context, event string, fields map[string]any) {
	if p.opts.Logger != nil {
		p.opts.Logger(ctx, event, fields)
	}
}

type ItemResult struct {
	Target  string `json:"target"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}
type PartialError struct {
	Succeeded int
	Failed    int
	Unknown   bool
}

func (e *PartialError) Error() string {
	return fmt.Sprintf("deployment partially completed: %d succeeded, %d failed", e.Succeeded, e.Failed)
}
func (e *PartialError) UnknownResult() bool { return e.Unknown }
func batch(ctx context.Context, targets []string, info Info, execute func(string) error) (Info, error) {
	if len(targets) == 0 {
		return info, errors.New("deployment targets are required")
	}
	results := []ItemResult{}
	failed := 0
	unknown := false
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return info, err
		}
		err := execute(target)
		item := ItemResult{Target: target, Success: err == nil}
		if err != nil {
			item.Error = err.Error()
			failed++
			var rejected *RejectedError
			var safe interface{ SafeToRetry() bool }
			if !errors.As(err, &rejected) && !errors.As(err, &safe) {
				unknown = true
			}
		}
		results = append(results, item)
	}
	info["results"] = results
	if failed > 0 {
		return info, &PartialError{Succeeded: len(results) - failed, Failed: failed, Unknown: unknown}
	}
	return info, nil
}
