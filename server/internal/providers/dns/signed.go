package dns

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func canonicalQuery(q url.Values) string { return strings.ReplaceAll(q.Encode(), "+", "%20") }
func canonicalHeaders(h http.Header, escape bool) (string, string) {
	keys := []string{}
	for k := range h {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	rows := []string{}
	for _, k := range keys {
		v := strings.TrimSpace(h.Get(k))
		if escape {
			rows = append(rows, percent(k)+":"+percent(v))
		} else {
			rows = append(rows, k+":"+v)
		}
	}
	return strings.Join(rows, "\n"), strings.Join(keys, ";")
}
func (b *base) signed(ctx context.Context, method, path string, q url.Values, body any) (map[string]any, error) {
	if q == nil {
		q = url.Values{}
	}
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	u, err := url.Parse(b.endpoint)
	if err != nil {
		return nil, err
	}
	host := u.Host
	date := b.now().UTC().Format("20060102T150405Z")
	h := http.Header{"Host": {host}}
	if body != nil {
		h.Set("Content-Type", "application/json")
	}
	key, secret := b.cfg["AccessKeyId"], b.cfg["SecretAccessKey"]
	if b.kind == "jdcloud" {
		secret = b.cfg["AccessKeySecret"]
	}
	if key == "" || secret == "" {
		return nil, errors.New("cloud access key credentials required")
	}
	switch b.kind {
	case "huawei":
		h.Set("X-Sdk-Date", date)
		canonical, signed := canonicalHeaders(h, false)
		uri := strings.TrimSuffix(path, "/") + "/"
		request := method + "\n" + uri + "\n" + canonicalQuery(q) + "\n" + canonical + "\n\n" + signed + "\n" + shaHex(raw)
		toSign := "SDK-HMAC-SHA256\n" + date + "\n" + shaHex([]byte(request))
		h.Set("Authorization", "SDK-HMAC-SHA256 Access="+key+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmac256([]byte(secret), toSign)))
	case "baidu":
		date = b.now().UTC().Format("2006-01-02T15:04:05Z")
		h.Set("X-Bce-Date", date)
		canonical, signed := canonicalHeaders(h, true)
		request := method + "\n" + path + "\n" + canonicalQuery(q) + "\n" + canonical
		auth := "bce-auth-v1/" + key + "/" + date + "/1800"
		signing := hex.EncodeToString(hmac256([]byte(secret), auth))
		h.Set("Authorization", auth+"/"+signed+"/"+hex.EncodeToString(hmac256([]byte(signing), request)))
	case "huoshan", "jdcloud":
		service, region, algorithm, term, prefix := "DNS", "cn-north-1", "HMAC-SHA256", "request", ""
		dateHeader := "X-Date"
		if b.kind == "jdcloud" {
			service, algorithm, term, prefix, dateHeader = "domainservice", "JDCLOUD2-HMAC-SHA256", "jdcloud2_request", "JDCLOUD2", "X-Jdcloud-Date"
			h.Set("X-Jdcloud-Algorithm", algorithm)
			h.Set("X-Jdcloud-Nonce", nonce())
		}
		h.Set(dateHeader, date)
		canonical, signed := canonicalHeaders(h, false)
		request := method + "\n" + path + "\n" + canonicalQuery(q) + "\n" + canonical + "\n\n" + signed + "\n" + shaHex(raw)
		scope := date[:8] + "/" + region + "/" + service + "/" + term
		toSign := algorithm + "\n" + date + "\n" + scope + "\n" + shaHex([]byte(request))
		signing := hmac256([]byte(prefix+secret), date[:8])
		signing = hmac256(signing, region)
		signing = hmac256(signing, service)
		signing = hmac256(signing, term)
		h.Set("Authorization", algorithm+" Credential="+key+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmac256(signing, toSign)))
	}
	raw, status, err := b.raw(ctx, method, path, q, raw, h)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 && status < 400 {
		return map[string]any{}, nil
	}
	out := map[string]any{}
	if err = decodeJSON(raw, &out); err != nil || out == nil {
		return nil, responseError(b.kind, status, methodWrites(method), "invalid JSON response")
	}
	remote := obj(out, "error")
	if b.kind == "huoshan" {
		remote = obj(obj(out, "ResponseMetadata"), "Error")
	}
	if status >= 400 || len(remote) > 0 || str(out, "error_msg") != "" || b.kind == "baidu" && str(out, "code") != "" {
		return nil, &RemoteError{Provider: b.kind, Status: status, Code: firstString(remote, "Code", "code"), Message: cloudErrorMessage(out, remote), UnknownResult: status >= 500 && methodWrites(method)}
	}
	if b.kind == "huoshan" {
		if _, ok := out["Result"].(map[string]any); !ok {
			return nil, responseError(b.kind, status, methodWrites(method), "missing Volcengine result envelope")
		}
		return obj(out, "Result"), nil
	}
	if b.kind == "jdcloud" {
		if _, ok := out["result"]; ok {
			return obj(out, "result"), nil
		}
	}
	return out, nil
}
func queryValues(m map[string]any) url.Values {
	q := url.Values{}
	for k, v := range m {
		if v != nil {
			q.Set(k, str(map[string]any{"v": v}, "v"))
		}
	}
	return q
}
func stringValues(m map[string]any, k string) []string {
	raw, _ := m[k].([]any)
	out := []string{}
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func intValue(s string) (int, error) { return strconv.Atoi(s) }

func cloudErrorMessage(out, remote map[string]any) string {
	if len(remote) > 0 {
		return firstString(remote, "MessageCN", "Message", "message", "error_msg")
	}
	return firstString(out, "error_msg", "message", "Message")
}
