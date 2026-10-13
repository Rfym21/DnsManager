package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type westProvider struct{ *httpProvider }

func (p *westProvider) call(ctx context.Context, values url.Values) (map[string]any, error) {
	values.Set("username", p.cfg["username"])
	timestamp := strconv.FormatInt(p.opts.Now().UnixMilli(), 10)
	values.Set("time", timestamp)
	values.Set("token", md5hex(p.cfg["username"]+p.cfg["api_password"]+timestamp))
	res, e := p.page(ctx, http.MethodPost, "/vhost/", values, nil)
	if e != nil {
		return nil, e
	}
	if res.code/100 != 2 {
		return nil, rejectedHTTP("west", res.code, "provider request failed")
	}
	raw := []byte(res.body)
	if !json.Valid(raw) {
		raw, e = simplifiedchinese.GBK.NewDecoder().Bytes(raw)
		if e != nil {
			return nil, errors.New("invalid West response encoding")
		}
	}
	var value map[string]any
	if e = json.Unmarshal(raw, &value); e != nil {
		return nil, errors.New("invalid West JSON")
	}
	if text(value["result"]) != "200" {
		return nil, errors.New(safeError(value, p.cfg))
	}
	return obj(value["data"]), nil
}
func (p *westProvider) Validate(ctx context.Context) error {
	if p.cfg["username"] == "" || p.cfg["api_password"] == "" {
		return errors.New("West API credentials are required")
	}
	_, e := p.call(ctx, url.Values{"act": {"products"}})
	return e
}
func (p *westProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, e := parsePair(chain, key); e != nil {
		return info, e
	}
	site := target.Config["sitename"]
	if site == "" {
		return info, errors.New("West FTP account is required")
	}
	data, e := p.call(ctx, url.Values{"act": {"vhostssl"}, "sitename": {site}, "cmd": {"info"}})
	if e != nil {
		return info, e
	}
	_, e = p.call(ctx, url.Values{"act": {"vhostssl"}, "sitename": {site}, "cmd": {"import"}, "keycontent": {key}, "certcontent": {chain}})
	if e != nil {
		return info, e
	}
	if !truth(data["SSLEnabled"]) {
		_, e = p.call(ctx, url.Values{"act": {"vhostssl"}, "sitename": {site}, "cmd": {"openssl"}})
		return info, e
	}
	data, e = p.call(ctx, url.Values{"act": {"vhostssl"}, "sitename": {site}, "cmd": {"info"}})
	if e != nil {
		return info, e
	}
	rows := obj(obj(data["sslcert"])["ssl"])
	ids := []string{}
	for domain := range rows {
		if matchesDomains([]string{domain}, target.Domains) {
			ids = append(ids, domain)
		}
	}
	if len(ids) == 0 {
		return info, nil
	}
	return batch(ctx, ids, info, func(domain string) error {
		_, e := p.call(ctx, url.Values{"act": {"vhostssl"}, "sitename": {site}, "cmd": {"clearsslcache"}, "sslid": {text(obj(rows[domain])["sysid"])}, "dm": {domain}})
		return e
	})
}

type ksyunProvider struct{ *httpProvider }

func (p *ksyunProvider) call(ctx context.Context, method, action, version, path string, body any) (map[string]any, error) {
	raw := []byte{}
	if method == http.MethodGet {
		values := url.Values{}
		for k, v := range obj(body) {
			values.Set(k, text(v))
		}
		if len(values) > 0 {
			path += "?" + values.Encode()
		}
	} else {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, p.base+path, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("X-Version", version)
	req.Header.Set("X-Action", action)
	if len(raw) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	signAWS(req, raw, p.cfg["AccessKeyId"], p.cfg["SecretAccessKey"], "cn-shanghai-2", "cdn", p.opts)
	resp, e := p.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	data, e := readLimited(resp.Body)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode/100 != 2 {
		return nil, rejectedHTTP("ksyun", resp.StatusCode, "provider request failed")
	}
	var m map[string]any
	if e = json.Unmarshal(data, &m); e != nil {
		return nil, errors.New("invalid Ksyun JSON")
	}
	if m["Error"] != nil {
		return nil, errors.New(safeError(m, p.cfg))
	}
	return m, nil
}
func (p *ksyunProvider) Validate(ctx context.Context) error {
	_, e := p.call(ctx, http.MethodGet, "GetCertificates", "2016-09-01", "/2016-09-01/cert/GetCertificates", nil)
	return e
}
func (p *ksyunProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	wanted := strings.Split(target.Config["domain"], ",")
	if len(wanted) == 0 || wanted[0] == "" {
		return info, errors.New("Ksyun domains are required")
	}
	found := map[string]string{}
	for page := 1; page <= 1000; page++ {
		data, e := p.call(ctx, http.MethodGet, "GetCdnDomains", "2019-06-01", "/2019-06-01/domain/GetCdnDomains", map[string]any{"PageSize": 100, "PageNumber": page})
		if e != nil {
			return info, e
		}
		rows := anyList(data["Domains"])
		for _, row := range rows {
			m := obj(row)
			found[text(m["DomainName"])] = text(m["DomainId"])
		}
		if len(rows) < 100 {
			break
		}
	}
	ids := []string{}
	for _, domain := range wanted {
		domain = strings.TrimSpace(domain)
		if found[domain] == "" {
			return info, fmt.Errorf("Ksyun domain %s not found", domain)
		}
		ids = append(ids, found[domain])
	}
	data, e := p.call(ctx, http.MethodPost, "ConfigCertificate", "2016-09-01", "/2016-09-01/cert/ConfigCertificate", map[string]any{"Enable": "on", "DomainIds": strings.Join(ids, ","), "CertificateName": certName(leaf.Subject.CommonName, leaf.NotBefore.Unix()), "ServerCertificate": chain, "PrivateKey": key})
	if e != nil {
		return info, e
	}
	info["certificate_id"] = text(data["CertificateId"])
	return info, nil
}
