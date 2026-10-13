package cert

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
	"sort"
	"strconv"
	"strings"
	"time"
)

type cloudProvider struct {
	kind     string
	cfg      map[string]string
	opts     Options
	endpoint string
}

func newCloud(kind string, cfg map[string]string, opts Options) (Provider, error) {
	endpoint := map[string]string{"tencent": "https://ssl.tencentcloudapi.com/", "aliyun": "https://cas.aliyuncs.com/", "ucloud": "https://api.ucloud.cn/", "huoshan": "https://open.volcengineapi.com/"}[kind]
	if opts.Endpoint != "" {
		endpoint = opts.Endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("invalid cloud API endpoint")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &cloudProvider{kind: kind, cfg: cfg, opts: opts, endpoint: strings.TrimRight(endpoint, "/") + "/"}, nil
}
func hmacBytes(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
func digest(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
func scalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}
func asMap(value any) map[string]any { m, _ := value.(map[string]any); return m }
func asList(value any) []any         { list, _ := value.([]any); return list }
func nonce() string                  { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func encodeQuery(params map[string]any) string {
	keys := []string{}
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, key := range keys {
		parts = append(parts, escape(key)+"="+escape(scalar(params[key])))
	}
	return strings.Join(parts, "&")
}
func escape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
func (p *cloudProvider) call(ctx context.Context, method, action string, params map[string]any, extra map[string]any) (any, error) {
	if params == nil {
		params = map[string]any{}
	}
	headers := map[string]string{}
	endpoint := p.endpoint
	body := []byte{}
	now := p.opts.Now().UTC()
	parsed, _ := url.Parse(endpoint)
	switch p.kind {
	case "tencent":
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		body = raw
		method = http.MethodPost
		service := "ssl"
		date := now.Format("2006-01-02")
		scope := date + "/" + service + "/tc3_request"
		canonical := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + parsed.Host + "\n\ncontent-type;host\n" + digest(string(body))
		timestamp := strconv.FormatInt(now.Unix(), 10)
		sign := "TC3-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + digest(canonical)
		key := hmacBytes(hmacBytes(hmacBytes([]byte("TC3"+p.cfg["SecretKey"]), date), service), "tc3_request")
		headers["Authorization"] = "TC3-HMAC-SHA256 Credential=" + p.cfg["SecretId"] + "/" + scope + ", SignedHeaders=content-type;host, Signature=" + hex.EncodeToString(hmacBytes(key, sign))
		headers["Content-Type"] = "application/json; charset=utf-8"
		headers["X-TC-Action"] = action
		headers["X-TC-Version"] = "2019-12-05"
		headers["X-TC-Timestamp"] = timestamp
	case "aliyun":
		signed := map[string]any{"Action": action, "Version": "2020-04-07", "Format": "JSON", "AccessKeyId": p.cfg["AccessKeyId"], "SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "SignatureNonce": nonce(), "Timestamp": now.Format("2006-01-02T15:04:05Z")}
		for k, v := range params {
			signed[k] = v
		}
		method = http.MethodPost
		canonical := encodeQuery(signed)
		mac := hmac.New(sha1.New, []byte(p.cfg["AccessKeySecret"]+"&"))
		mac.Write([]byte(method + "&%2F&" + escape(canonical)))
		signed["Signature"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
		body = []byte(encodeQuery(signed))
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	case "ucloud":
		signed := map[string]any{"Action": action, "PublicKey": p.cfg["PublicKey"]}
		for k, v := range params {
			signed[k] = v
		}
		keys := []string{}
		for k := range signed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		canonical := ""
		for _, k := range keys {
			canonical += k + scalar(signed[k])
		}
		hash := sha1.Sum([]byte(canonical + p.cfg["PrivateKey"]))
		signed["Signature"] = hex.EncodeToString(hash[:])
		body, _ = json.Marshal(signed)
		method = http.MethodPost
		headers["Content-Type"] = "application/json"
	case "huoshan":
		query := map[string]any{"Action": action, "Version": "2021-06-01"}
		if method == http.MethodGet {
			for k, v := range params {
				query[k] = v
			}
		} else {
			body, _ = json.Marshal(params)
			headers["Content-Type"] = "application/json"
			for k, v := range extra {
				query[k] = v
			}
		}
		date := now.Format("20060102T150405Z")
		short := now.Format("20060102")
		headers["Host"] = parsed.Host
		headers["X-Date"] = date
		lower := map[string]string{}
		keys := []string{}
		for k, v := range headers {
			key := strings.ToLower(k)
			lower[key] = v
			keys = append(keys, key)
		}
		sort.Strings(keys)
		canonicalHeaders := ""
		for _, k := range keys {
			canonicalHeaders += k + ":" + lower[k] + "\n"
		}
		signedHeaders := strings.Join(keys, ";")
		canonical := method + "\n/\n" + encodeQuery(query) + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + digest(string(body))
		scope := short + "/cn-north-1/certificate_service/request"
		sign := "HMAC-SHA256\n" + date + "\n" + scope + "\n" + digest(canonical)
		key := hmacBytes(hmacBytes(hmacBytes(hmacBytes([]byte(p.cfg["SecretAccessKey"]), short), "cn-north-1"), "certificate_service"), "request")
		headers["Authorization"] = "HMAC-SHA256 Credential=" + p.cfg["AccessKeyId"] + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + hex.EncodeToString(hmacBytes(key, sign))
		endpoint += "?" + encodeQuery(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := p.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, &UnknownError{Message: p.kind + " " + action + " 请求结果未确认"}
	}
	defer resp.Body.Close()
	var value any
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil || len(raw) > 16<<20 {
		return nil, &UnknownError{Message: "证书平台响应未完整读取"}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&value); err != nil {
		return nil, &UnknownError{Message: "证书平台响应格式未确认"}
	}
	m := asMap(value)
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 408 {
			return nil, &RejectedError{Message: fmt.Sprintf("cloud API returned HTTP %d", resp.StatusCode)}
		}
		return nil, &UnknownError{Message: fmt.Sprintf("cloud API returned HTTP %d; result unknown", resp.StatusCode)}
	}
	switch p.kind {
	case "tencent":
		m = asMap(m["Response"])
		if errorObj := asMap(m["Error"]); len(errorObj) > 0 {
			return nil, &RejectedError{Message: fmt.Sprintf("Tencent %s: %s", scalar(errorObj["Code"]), redact(scalar(errorObj["Message"]), p.cfg))}
		}
		return m, nil
	case "aliyun":
		if code := scalar(m["Code"]); code != "" && code != "Success" {
			return nil, &RejectedError{Message: fmt.Sprintf("Aliyun %s: %s", code, redact(scalar(m["Message"]), p.cfg))}
		}
	case "ucloud":
		if scalar(m["RetCode"]) != "0" {
			return nil, &RejectedError{Message: redact(scalar(m["Message"]), p.cfg)}
		}
	case "huoshan":
		metadata := asMap(m["ResponseMetadata"])
		if errorObj := asMap(metadata["Error"]); len(errorObj) > 0 {
			return nil, &RejectedError{Message: redact(scalar(errorObj["Message"]), p.cfg)}
		}
		return m["Result"], nil
	}
	return m, nil
}
func redact(message string, cfg map[string]string) string {
	for _, v := range cfg {
		if len(v) > 3 {
			message = strings.ReplaceAll(message, v, "[redacted]")
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
