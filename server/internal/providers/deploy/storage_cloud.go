package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}
func awsEscape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
func signAWS(req *http.Request, body []byte, access, secret, region, service string, opts Options) {
	now := opts.Now().UTC()
	date := now.Format("20060102T150405Z")
	short := now.Format("20060102")
	hash := sha256hex(body)
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("X-Amz-Content-Sha256", hash)
	headers := map[string]string{"host": req.URL.Host}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if lower == "authorization" {
			continue
		}
		headers[lower] = strings.TrimSpace(strings.Join(values, ","))
	}
	keys := []string{}
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	canonicalHeaders := ""
	for _, key := range keys {
		canonicalHeaders += key + ":" + headers[key] + "\n"
	}
	signed := strings.Join(keys, ";")
	query := req.URL.Query()
	qkeys := []string{}
	for key := range query {
		qkeys = append(qkeys, key)
	}
	sort.Strings(qkeys)
	parts := []string{}
	for _, key := range qkeys {
		values := query[key]
		sort.Strings(values)
		for _, value := range values {
			parts = append(parts, awsEscape(key)+"="+awsEscape(value))
		}
	}
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonical := req.Method + "\n" + canonicalURI + "\n" + strings.Join(parts, "&") + "\n" + canonicalHeaders + "\n" + signed + "\n" + hash
	scope := short + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + sha256hex([]byte(canonical))
	key := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+secret), short), region), service), "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+access+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmacSHA256(key, toSign)))
}

type s3Provider struct{ *httpProvider }

func (p *s3Provider) call(ctx context.Context, method, path string, body []byte) error {
	req, e := http.NewRequestWithContext(ctx, method, p.base+path, bytes.NewReader(body))
	if e != nil {
		return e
	}
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/x-pem-file")
	}
	region := p.cfg["region"]
	if region == "" {
		region = "us-east-1"
	}
	signAWS(req, body, p.cfg["AccessKeyId"], p.cfg["SecretAccessKey"], region, "s3", p.opts)
	resp, e := p.client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return rejectedHTTP("s3storage", resp.StatusCode, "provider request failed")
	}
	return nil
}
func (p *s3Provider) Validate(ctx context.Context) error {
	if p.cfg["AccessKeyId"] == "" || p.cfg["SecretAccessKey"] == "" {
		return errors.New("S3 credentials are required")
	}
	return p.call(ctx, http.MethodGet, "/", nil)
}
func (p *s3Provider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, e := parsePair(chain, key); e != nil {
		return info, e
	}
	bucket := target.Config["bucket"]
	certPath := strings.Trim(target.Config["cert_path"], "/")
	keyPath := strings.Trim(target.Config["key_path"], "/")
	if bucket == "" || certPath == "" || keyPath == "" || certPath == keyPath || strings.Contains(bucket, "/") {
		return info, errors.New("S3 bucket and distinct object paths are required")
	}
	paths := []string{certPath, keyPath}
	content := map[string]string{certPath: chain, keyPath: key}
	return batch(ctx, paths, info, func(path string) error {
		return p.call(ctx, http.MethodPut, "/"+url.PathEscape(bucket)+"/"+escapeObjectPath(path), []byte(content[path]))
	})
}

func escapeObjectPath(path string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

type qiniuProvider struct{ *httpProvider }

func (p *qiniuProvider) call(ctx context.Context, method, path string, body any, pili bool) (any, error) {
	raw := []byte{}
	if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	base := p.base
	signString := path + "\n"
	prefix := "QBox "
	if pili {
		base = "https://pili.qiniuapi.com"
		if p.cfg["pili_endpoint"] != "" {
			base = p.cfg["pili_endpoint"]
		}
		u, _ := url.Parse(base)
		signString = method + " " + path + "\nHost: " + u.Host
		if body != nil {
			signString += "\nContent-Type: application/json"
		}
		signString += "\n\n" + string(raw)
		prefix = "Qiniu "
	}
	mac := hmac.New(sha1.New, []byte(p.cfg["SecretKey"]))
	mac.Write([]byte(signString))
	q := *p.httpProvider
	q.base = strings.TrimRight(base, "/")
	headers := map[string]string{"Authorization": prefix + p.cfg["AccessKey"] + ":" + base64.URLEncoding.EncodeToString(mac.Sum(nil))}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	return q.request(ctx, method, path, raw, headers)
}
func (p *qiniuProvider) Validate(ctx context.Context) error {
	if p.cfg["AccessKey"] == "" || p.cfg["SecretKey"] == "" {
		return errors.New("Qiniu credentials are required")
	}
	_, e := p.call(ctx, http.MethodGet, "/sslcert", nil, false)
	return e
}
func (p *qiniuProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	info = renewedInfo(prior, sha256hex(leaf.Raw), "cert_id", "cert_name")
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	id := text(info["cert_id"])
	if id == "" {
		marker := ""
		seen := map[string]bool{}
		for page := 0; page < 1000; page++ {
			v, e := p.call(ctx, http.MethodGet, "/sslcert?"+url.Values{"marker": {marker}, "limit": {"100"}}.Encode(), nil, false)
			if e != nil {
				return info, e
			}
			m := obj(v)
			for _, row := range anyList(m["certs"]) {
				item := obj(row)
				if text(item["name"]) == name {
					id = text(item["certid"])
					break
				}
			}
			if id != "" {
				break
			}
			marker = text(m["marker"])
			if marker == "" {
				break
			}
			if seen[marker] {
				return info, errors.New("Qiniu pagination repeated marker")
			}
			seen[marker] = true
		}
	}
	if id == "" {
		v, e := p.call(ctx, http.MethodPost, "/sslcert", map[string]string{"name": name, "common_name": leaf.Subject.CommonName, "pri": key, "ca": chain}, false)
		if e != nil {
			return info, e
		}
		id = text(obj(v)["certID"])
		if id == "" {
			return info, errors.New("Qiniu upload returned no certificate ID")
		}
		info["cert_id"] = id
		info["cert_name"] = name
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
	}
	if target.Config["product"] == "upload" {
		return info, nil
	}
	return batch(ctx, strings.Split(target.Config["domain"], ","), info, func(domain string) error {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return errors.New("Qiniu domain is required")
		}
		switch target.Config["product"] {
		case "cdn":
			path := "/domain/" + url.PathEscape(domain)
			v, e := p.call(ctx, http.MethodGet, path, nil, false)
			if e != nil {
				return e
			}
			https := obj(obj(v)["https"])
			if text(https["certId"]) == id {
				return nil
			}
			body := map[string]any{"certid": id}
			suffix := "/sslize"
			if text(https["certId"]) != "" {
				suffix = "/httpsconf"
				body["forceHttps"] = https["forceHttps"]
				body["http2Enable"] = https["http2Enable"]
			}
			_, e = p.call(ctx, http.MethodPut, path+suffix, body, false)
			return e
		case "oss":
			_, e := p.call(ctx, http.MethodPost, "/cert/bind", map[string]string{"certid": id, "domain": domain}, false)
			return e
		case "pili":
			hub := target.Config["pili_hub"]
			if hub == "" {
				return errors.New("Qiniu Pili hub is required")
			}
			_, e := p.call(ctx, http.MethodPost, "/v2/hubs/"+url.PathEscape(hub)+"/domains/"+url.PathEscape(domain)+"/cert", map[string]string{"CertName": name}, true)
			return e
		default:
			return errors.New("invalid Qiniu product")
		}
	})
}

type ucloudDeployProvider struct{ *httpProvider }

func (p *ucloudDeployProvider) call(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	body := map[string]any{"Action": action, "PublicKey": p.cfg["PublicKey"]}
	for k, v := range params {
		body[k] = v
	}
	keys := []string{}
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	str := ""
	for _, k := range keys {
		str += k + text(body[k])
	}
	hash := sha1.Sum([]byte(str + p.cfg["PrivateKey"]))
	body["Signature"] = hex.EncodeToString(hash[:])
	v, e := p.json(ctx, http.MethodPost, "/", body, nil)
	if e != nil {
		return nil, e
	}
	if text(obj(v)["RetCode"]) != "0" {
		return nil, errors.New(safeError(v, p.cfg))
	}
	return obj(v), nil
}
func (p *ucloudDeployProvider) Validate(ctx context.Context) error {
	if p.cfg["PublicKey"] == "" || p.cfg["PrivateKey"] == "" {
		return errors.New("UCloud credentials are required")
	}
	_, e := p.call(ctx, "GetCertificateList", map[string]any{"Mode": "free"})
	return e
}
func (p *ucloudDeployProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	info = renewedInfo(prior, sha256hex(leaf.Raw), "cert_id", "cert_name")
	resource := target.Config["domain_id"]
	if resource == "" {
		return info, errors.New("UCloud resource ID is required")
	}
	name := strings.ReplaceAll(strings.ReplaceAll(leaf.Subject.CommonName, "*", ""), ".", "") + "-" + strconv.FormatInt(leaf.NotBefore.Unix(), 10)
	if _, e = p.call(ctx, "AddCertificate", map[string]any{"CertName": name, "UserCert": chain, "PrivateKey": key}); e != nil && !strings.Contains(e.Error(), "cert already exist") {
		return info, e
	}
	data, e := p.call(ctx, "GetUcdnDomainConfig", map[string]any{"DomainId.0": resource})
	if e != nil {
		return info, e
	}
	rows := anyList(data["DomainList"])
	if len(rows) != 1 {
		return info, errors.New("UCloud domain resource not found")
	}
	row := obj(rows[0])
	v, e := p.call(ctx, "GetCertificateBaseInfoList", map[string]any{"Domain": text(row["Domain"])})
	if e != nil {
		return info, e
	}
	id := ""
	for _, cert := range anyList(v["CertList"]) {
		m := obj(cert)
		if text(m["CertName"]) == name {
			id = text(m["CertId"])
			break
		}
	}
	if id == "" {
		return info, errors.New("UCloud certificate ID unavailable")
	}
	info["cert_id"] = id
	info["cert_name"] = name
	if e = persist(ctx, p.opts, info); e != nil {
		return info, e
	}
	params := map[string]any{"DomainId": resource, "CertName": name, "CertId": id, "CertType": "ucdn"}
	if text(row["HttpsStatusCn"]) == "enable" {
		params["HttpsStatusCn"] = "enable"
	}
	if text(row["HttpsStatusAbroad"]) == "enable" {
		params["HttpsStatusAbroad"] = "enable"
	}
	if params["HttpsStatusCn"] == nil && params["HttpsStatusAbroad"] == nil {
		params["HttpsStatusCn"] = "enable"
	}
	_, e = p.call(ctx, "UpdateUcdnDomainHttpsConfigV2", params)
	return info, e
}
