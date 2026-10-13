package dns

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type RemoteError struct {
	Provider      string
	Status        int
	Code          string
	Message       string
	UnknownResult bool
}
type PartialWriteError struct {
	Provider, RecordID, Message string
	Cause                       error
}

func (e *PartialWriteError) Error() string { return e.Provider + ": " + e.Message }
func (e *PartialWriteError) Unwrap() error { return e.Cause }

func (e *RemoteError) Error() string {
	if e.UnknownResult {
		return e.Provider + ": request failed; remote write result may be unknown"
	}
	// Remote message bodies can reflect credentials, DNS challenge values or
	// submitted records. Keep them out of persistent/public error strings.
	return fmt.Sprintf("%s: DNS request rejected (HTTP %d)", e.Provider, e.Status)
}
func uncertainWrite(mutation bool, status int) bool {
	return mutation && (status < 400 || status >= 500)
}
func methodWrites(method string) bool { return method != "GET" && method != "HEAD" }
func responseError(provider string, status int, mutation bool, message string) error {
	return &RemoteError{Provider: provider, Status: status, UnknownResult: uncertainWrite(mutation, status), Message: message}
}
func classifyProtocolError(err error, mutation bool) error {
	var remote *RemoteError
	if errors.As(err, &remote) {
		remote.UnknownResult = uncertainWrite(mutation, remote.Status)
	}
	return err
}
func acceptedWriteError(provider string, err error) error {
	if err == nil {
		return nil
	}
	return &RemoteError{Provider: provider, UnknownResult: true, Message: "accepted write could not be fully confirmed"}
}
func decodeJSON(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON response")
	}
	return nil
}
func (b *base) raw(ctx context.Context, method, path string, query url.Values, body []byte, headers http.Header) ([]byte, int, error) {
	u := b.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header[k] = append([]string(nil), v...)
	}
	res, err := b.client.Do(req)
	if err != nil {
		return nil, 0, &RemoteError{Provider: b.kind, UnknownResult: method != "GET" && method != "HEAD", Message: "network request failed"}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 16<<20+1))
	if err != nil {
		return nil, res.StatusCode, responseError(b.kind, res.StatusCode, methodWrites(method), "DNS response read failed")
	}
	if len(data) > 16<<20 {
		return nil, res.StatusCode, responseError(b.kind, res.StatusCode, methodWrites(method), "DNS response exceeds limit")
	}
	return data, res.StatusCode, nil
}
func (b *base) json(ctx context.Context, method, path string, query url.Values, body any, headers http.Header) (map[string]any, int, error) {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		if headers == nil {
			headers = http.Header{}
		}
		headers.Set("Content-Type", "application/json")
	}
	raw, status, err := b.raw(ctx, method, path, query, encoded, headers)
	if err != nil {
		return nil, status, err
	}
	if len(raw) == 0 && status < 400 {
		return map[string]any{}, status, nil
	}
	var out map[string]any
	if err = decodeJSON(raw, &out); err != nil || out == nil {
		return nil, status, responseError(b.kind, status, methodWrites(method), "invalid JSON response")
	}
	if status >= 400 {
		uncertain := status >= 500 && method != "GET" && method != "HEAD"
		if es := arr(out, "errors"); len(es) > 0 {
			return out, status, &RemoteError{Provider: b.kind, Status: status, Code: str(es[0], "code"), Message: str(es[0], "message"), UnknownResult: uncertain}
		}
		return out, status, &RemoteError{Provider: b.kind, Status: status, Code: str(out, "Code"), Message: firstString(out, "Message", "message", "error", "error_description"), UnknownResult: uncertain}
	}
	return out, status, nil
}
func obj(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}
func arr(m map[string]any, k string) []map[string]any {
	a, _ := m[k].([]any)
	out := make([]map[string]any, 0, len(a))
	for _, v := range a {
		if row, ok := v.(map[string]any); ok {
			out = append(out, row)
		}
	}
	return out
}
func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}
func integer(m map[string]any, k string) int { n, _ := strconv.Atoi(str(m, k)); return n }
func boolean(m map[string]any, k string) bool {
	v := str(m, k)
	return v == "true" || v == "1" || v == "ENABLE" || v == "enabled"
}
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := str(m, k); s != "" {
			return s
		}
	}
	return "remote request rejected"
}
func optionalInt(m map[string]any, k string) *int {
	if _, ok := m[k]; !ok || m[k] == nil {
		return nil
	}
	n := integer(m, k)
	return &n
}
func jsonRaw(v any) json.RawMessage { data, _ := json.Marshal(v); return data }
func nonce() string                 { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func shaHex(b []byte) string        { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func hmac256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}
func hmac1(key, s string) string {
	m := hmac.New(sha1.New, []byte(key))
	m.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}
func percent(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
func pathID(s string) string  { return url.PathEscape(s) }
func domainPage(rows []Domain, o ListOptions) DomainPage {
	o = normalizedOptions(o)
	filtered := []Domain{}
	for _, d := range rows {
		if o.Keyword == "" || strings.Contains(strings.ToLower(d.Name), strings.ToLower(o.Keyword)) {
			filtered = append(filtered, d)
		}
	}
	total := len(filtered)
	start := (o.Page - 1) * o.PageSize
	if start > total {
		start = total
	}
	end := min(start+o.PageSize, total)
	return DomainPage{Total: total, Rows: filtered[start:end]}
}
func recordPage(rows []Record, o ListOptions) RecordPage {
	o = normalizedOptions(o)
	filtered := []Record{}
	for _, r := range rows {
		if o.Name != "" && !strings.EqualFold(r.Name, o.Name) {
			continue
		}
		if o.Type != "" && !strings.EqualFold(r.Type, o.Type) {
			continue
		}
		if o.Value != "" && r.Value != o.Value {
			found := false
			for _, v := range r.Values {
				if v == o.Value {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if o.Line != "" && r.Line != o.Line {
			continue
		}
		if o.Enabled != nil && r.Enabled != *o.Enabled {
			continue
		}
		if o.Keyword != "" && !strings.Contains(strings.ToLower(r.Name+" "+r.Value), strings.ToLower(o.Keyword)) {
			continue
		}
		filtered = append(filtered, r)
	}
	total := len(filtered)
	start := (o.Page - 1) * o.PageSize
	if start > total {
		start = total
	}
	end := min(start+o.PageSize, total)
	return RecordPage{Total: total, Rows: filtered[start:end]}
}
