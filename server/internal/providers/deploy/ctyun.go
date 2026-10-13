package deploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type ctyunProvider struct{ *httpProvider }

func (p *ctyunProvider) call(ctx context.Context, product, method, path string, body any, extra map[string]string) (map[string]any, error) {
	endpoint := map[string]string{"cdn": "ctcdn-global.ctapi.ctyun.cn", "icdn": "icdn-global.ctapi.ctyun.cn", "accessone": "accessone-global.ctapi.ctyun.cn", "cf": "cf-global.ctapi.ctyun.cn"}[product]
	base := "https://" + endpoint
	if p.cfg["url"] != "" {
		base = p.base
	}
	raw := []byte{}
	if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	date := p.opts.Now().UTC().Format("20060102T150405Z")
	headers := map[string]string{"host": req.URL.Host, "eop-date": date, "ctyun-eop-request-id": randomSuffix()}
	if body != nil {
		headers["content-type"] = "application/json"
	}
	for k, v := range extra {
		headers[strings.ToLower(k)] = v
	}
	keys := []string{}
	for k := range headers {
		keys = append(keys, k)
		if k != "host" {
			req.Header.Set(k, headers[k])
		}
	}
	sort.Strings(keys)
	canonical := ""
	for _, k := range keys {
		canonical += k + ":" + headers[k] + "\n"
	}
	toSign := canonical + "\n" + strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20") + "\n" + sha256hex(raw)
	key := hmacSHA256(hmacSHA256(hmacSHA256([]byte(p.cfg["SecretAccessKey"]), date), p.cfg["AccessKeyId"]), date[:8])
	req.Header.Set("Eop-Authorization", p.cfg["AccessKeyId"]+" Headers="+strings.Join(keys, ";")+" Signature="+base64.StdEncoding.EncodeToString(hmacSHA256(key, toSign)))
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
		return nil, rejectedHTTP("ctyun", resp.StatusCode, "provider request failed")
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil {
		return nil, errors.New("invalid Ctyun JSON")
	}
	code := text(value["statusCode"])
	if code != "100000" && !(code == "0" && product == "cf") {
		return nil, errors.New(safeError(value, p.cfg))
	}
	return obj(value["returnObj"]), nil
}
func (p *ctyunProvider) Validate(ctx context.Context) error {
	if p.cfg["AccessKeyId"] == "" || p.cfg["SecretAccessKey"] == "" {
		return errors.New("Ctyun credentials are required")
	}
	_, e := p.call(ctx, "cdn", http.MethodGet, "/v1/cert/query-cert-list", nil, nil)
	return e
}
func (p *ctyunProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	product := target.Config["product"]
	if product != "cdn" && product != "icdn" && product != "accessone" && product != "cf" {
		return info, errors.New("invalid Ctyun product")
	}
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	if product != "cf" {
		path := "/v1/cert/creat-cert"
		if product == "accessone" {
			path = "/ctapi/v1/accessone/cert/create"
		}
		_, e = p.call(ctx, product, http.MethodPost, path, map[string]string{"name": name, "key": key, "certs": chain}, nil)
		if e != nil && !strings.Contains(e.Error(), "已存在重名的证书") {
			return info, e
		}
	}
	return batch(ctx, splitLines(strings.ReplaceAll(target.Config["domain"], ",", "\n")), info, func(domain string) error {
		switch product {
		case "cdn", "icdn":
			_, e := p.call(ctx, product, http.MethodPost, "/v1/domain/update-domain", map[string]string{"domain": domain, "https_status": "on", "cert_name": name}, nil)
			return e
		case "accessone":
			data, e := p.call(ctx, product, http.MethodPost, "/ctapi/v1/accessone/domain/config", map[string]string{"domain": domain, "product_code": "020"}, nil)
			if e != nil {
				return e
			}
			data["https_status"] = "on"
			data["cert_name"] = name
			for _, field := range []string{"status", "area_scope", "cname", "insert_date", "status_date", "record_status", "record_num", "customer_name", "outlink_replace_filter", "website_ipv6_access_mark", "websocket_speed", "dynamic_config", "dynamic_ability"} {
				delete(data, field)
			}
			for _, origin := range anyList(data["origin"]) {
				m := obj(origin)
				m["weight"] = text(m["weight"])
			}
			_, e = p.call(ctx, product, http.MethodPost, "/ctapi/v1/scdn/domain/modify_config", data, nil)
			return e
		case "cf":
			if target.Config["region_id"] == "" {
				return errors.New("Ctyun function region is required")
			}
			path := "/openapi/v1/domains/customdomains/" + url.PathEscape(domain)
			headers := map[string]string{"regionId": target.Config["region_id"]}
			data, e := p.call(ctx, product, http.MethodGet, path, nil, headers)
			if e != nil {
				return e
			}
			protocol := text(data["protocol"])
			if protocol == "HTTP" {
				protocol = "HTTP,HTTPS"
			}
			_, e = p.call(ctx, product, http.MethodPut, path, map[string]any{"domainName": domain, "description": data["description"], "protocol": protocol, "certConfig": map[string]string{"certName": name, "certificate": chain, "privateKey": key}, "authConfig": data["authConfig"], "routeConfig": data["routeConfig"]}, headers)
			return e
		}
		return nil
	})
}
