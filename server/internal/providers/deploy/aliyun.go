package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type aliyunProvider struct{ *httpProvider }

func newAliyun(cfg map[string]string, opts Options) (Provider, error) {
	copy := map[string]string{}
	for k, v := range cfg {
		copy[k] = v
	}
	if copy["url"] == "" {
		copy["url"] = "https://cas.aliyuncs.com"
	}
	p, err := newHTTP("aliyun", copy, opts)
	if err != nil {
		return nil, err
	}
	p.cfg = cfg
	if cfg["AccessKeyId"] == "" || cfg["AccessKeySecret"] == "" {
		return nil, errors.New("Aliyun AccessKeyId and AccessKeySecret are required")
	}
	return &aliyunProvider{p}, nil
}
func aliyunEscape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
func aliyunQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, aliyunEscape(k)+"="+aliyunEscape(params[k]))
	}
	return strings.Join(parts, "&")
}
func aliyunNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
func (p *aliyunProvider) endpoint(host string) string {
	if p.cfg["url"] != "" {
		return p.base
	}
	return "https://" + host
}

func aliyunBindIdentity(product string, target Target) string {
	values := map[string]string{"product": product}
	for key, value := range target.Config {
		values[key] = value
	}
	return sha256hex([]byte(aliyunQuery(values) + "\n" + strings.Join(target.Domains, "\n")))
}

func (p *aliyunProvider) ValidateTarget(target Target) error {
	product := target.Config["product"]
	if product == "" {
		product = "cdn"
	}
	fields := map[string][]string{
		"api": {"api_groupid"}, "fc": {"fc_cname"}, "fc2": {"fc_cname"},
		"esa": {"esa_sitename"}, "esa_saas": {"esa_sitename", "esa_saas_sitename"},
		"oss": {"oss_endpoint", "oss_bucket"}, "wafres": {"waf_resource_id"},
		"clb": {"clb_id", "clb_port"}, "alb": {"alb_listener_id"},
		"nlb": {"nlb_listener_id"}, "ga": {"ga_id", "ga_listener_id"},
	}
	if err := aliyunRequire(target.Config, fields[product]...); err != nil {
		return err
	}
	if (product == "clb" || product == "ga") && target.Config["deploy_type"] == "1" {
		return aliyunRequire(target.Config, "clb_domain")
	}
	return nil
}
func (p *aliyunProvider) rpc(ctx context.Context, host, version, method, action string, body map[string]string) (map[string]any, error) {
	nonce, err := aliyunNonce()
	if err != nil {
		return nil, err
	}
	params := map[string]string{"Format": "JSON", "Version": version, "AccessKeyId": p.cfg["AccessKeyId"], "SignatureMethod": "HMAC-SHA1", "Timestamp": p.opts.Now().UTC().Format("2006-01-02T15:04:05Z"), "SignatureVersion": "1.0", "SignatureNonce": nonce, "Action": action}
	for k, v := range body {
		params[k] = v
	}
	unsigned := aliyunQuery(params)
	mac := hmac.New(sha1.New, []byte(p.cfg["AccessKeySecret"]+"&"))
	mac.Write([]byte(method + "&%2F&" + aliyunEscape(unsigned)))
	params["Signature"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	encoded := aliyunQuery(params)
	endpoint := p.endpoint(host) + "/"
	raw := []byte(encoded)
	if method == http.MethodGet {
		endpoint += "?" + encoded
		raw = nil
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("X-Dnsmgr-Provider-Endpoint", host)
	return p.decodeAliyun(req)
}
func (p *aliyunProvider) decodeAliyun(req *http.Request) (map[string]any, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Aliyun request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := readLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 && resp.StatusCode/100 == 2 {
		return map[string]any{}, nil
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil {
		if resp.StatusCode/100 != 2 {
			return nil, rejectedHTTP("Aliyun", resp.StatusCode, "provider request failed")
		}
		return nil, fmt.Errorf("Aliyun returned invalid JSON (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 || result["Code"] != nil && text(result["Code"]) != "200" && text(result["Code"]) != "Success" {
		message := text(result["Message"])
		code := text(result["Code"])
		retryable := code == "Throttling" || strings.HasPrefix(code, "Throttling.") || code == "ThrottlingUser"
		if retryable || resp.StatusCode/100 == 2 {
			return nil, &RejectedError{Provider: "Aliyun", Status: resp.StatusCode, Message: safeError(map[string]any{"message": message}, p.cfg), Retryable: retryable}
		}
		return nil, rejectedHTTP("Aliyun", resp.StatusCode, safeError(map[string]any{"message": message}, p.cfg))
	}
	return result, nil
}
func (p *aliyunProvider) acs3(ctx context.Context, host, version, method, action, path string, body map[string]any) (map[string]any, error) {
	raw := []byte{}
	query := map[string]string{}
	if method == http.MethodGet || method == http.MethodDelete {
		for k, v := range body {
			query[k] = text(v)
		}
	} else if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	endpoint := p.endpoint(host) + path
	if len(query) > 0 {
		endpoint += "?" + aliyunQuery(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	nonce, err := aliyunNonce()
	if err != nil {
		return nil, err
	}
	headers := map[string]string{"host": req.URL.Host, "x-acs-action": action, "x-acs-version": version, "x-acs-date": p.opts.Now().UTC().Format("2006-01-02T15:04:05Z"), "x-acs-signature-nonce": nonce, "x-acs-content-sha256": sha256hex(raw)}
	if len(raw) > 0 {
		headers["content-type"] = "application/json; charset=utf-8"
	}
	keys := []string{}
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	canonical := ""
	for _, k := range keys {
		canonical += k + ":" + strings.TrimSpace(headers[k]) + "\n"
		if k != "host" {
			req.Header.Set(k, headers[k])
		}
	}
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = aliyunEscape(s)
	}
	signed := strings.Join(keys, ";")
	request := method + "\n" + strings.Join(segments, "/") + "\n" + aliyunQuery(query) + "\n" + canonical + "\n" + signed + "\n" + sha256hex(raw)
	signature := hex.EncodeToString(hmacSHA256([]byte(p.cfg["AccessKeySecret"]), "ACS3-HMAC-SHA256\n"+sha256hex([]byte(request))))
	req.Header.Set("Authorization", "ACS3-HMAC-SHA256 Credential="+p.cfg["AccessKeyId"]+",SignedHeaders="+signed+",Signature="+signature)
	req.Header.Set("X-Dnsmgr-Provider-Endpoint", host)
	return p.decodeAliyun(req)
}
func (p *aliyunProvider) oss(ctx context.Context, endpoint, bucket, domain, certificateID string) error {
	type certConfig struct {
		CertID string `xml:"CertId"`
		Force  string `xml:"Force"`
	}
	type cname struct {
		Domain      string     `xml:"Domain"`
		Certificate certConfig `xml:"CertificateConfiguration"`
	}
	type configuration struct {
		XMLName xml.Name `xml:"BucketCnameConfiguration"`
		Cname   cname    `xml:"Cname"`
	}
	raw, err := xml.Marshal(configuration{Cname: cname{Domain: domain, Certificate: certConfig{certificateID, "true"}}})
	if err != nil {
		return err
	}
	host := bucket + "." + strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	date := p.opts.Now().UTC().Format(http.TimeFormat)
	sign := "POST\n\napplication/xml\n" + date + "\n/" + bucket + "/?cname&comp=add"
	mac := hmac.New(sha1.New, []byte(p.cfg["AccessKeySecret"]))
	mac.Write([]byte(sign))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint(host)+"/?cname&comp=add", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", "OSS "+p.cfg["AccessKeyId"]+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return rejectedHTTP("aliyun", resp.StatusCode, "OSS request failed")
	}
	return nil
}
func (p *aliyunProvider) Validate(ctx context.Context) error {
	_, err := p.rpc(ctx, "cas.aliyuncs.com", "2020-04-07", http.MethodPost, "ListUserCertificateOrder", nil)
	return err
}
func aliyunTargets(value string, fallback []string) []string {
	seen := map[string]bool{}
	result := []string{}
	if value != "" {
		fallback = strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	}
	for _, v := range fallback {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}
	return result
}
func aliyunRequire(cfg map[string]string, keys ...string) error {
	for _, key := range keys {
		if strings.TrimSpace(cfg[key]) == "" {
			return fmt.Errorf("Aliyun target %s is required", key)
		}
	}
	return nil
}
func (p *aliyunProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if err := p.ValidateTarget(target); err != nil {
		return info, err
	}
	leaf, _, _, err := parsePair(chain, key)
	if err != nil {
		return info, err
	}
	cfg := target.Config
	product := cfg["product"]
	if product == "" {
		product = "cdn"
	}
	domains := aliyunTargets(cfg["domain"], target.Domains)
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	region := cfg["region"]
	if region == "" {
		region = "cn-hangzhou"
	}
	regionID := cfg["regionid"]
	if regionID == "" {
		regionID = region
	}
	if product == "api" || product == "vod" || product == "fc" || product == "fc2" {
		return p.inlineDeploy(ctx, chain, key, name, product, regionID, cfg, domains, info)
	}
	switch product {
	case "cdn", "dcdn", "esa", "oss", "waf", "wafres", "waf2", "ddoscoo", "live", "clb", "alb", "nlb", "esa_saas", "ga", "upload":
	default:
		return info, fmt.Errorf("unknown Aliyun deployment product %q", product)
	}
	fingerprint := sha256hex(leaf.Raw)
	id := text(info["cert_id"])
	if text(info["certificate_fingerprint"]) != fingerprint || text(info["cert_region"]) != region {
		id = ""
	}
	if id == "" {
		host := "cas.aliyuncs.com"
		if region == "ap-southeast-1" {
			host = "cas.ap-southeast-1.aliyuncs.com"
		}
		orders, e := p.rpc(ctx, host, "2020-04-07", http.MethodPost, "ListUserCertificateOrder", map[string]string{"Keyword": leaf.Subject.CommonName, "OrderType": "CERT"})
		if e != nil {
			return info, e
		}
		serial := strings.TrimLeft(strings.ToLower(leaf.SerialNumber.Text(16)), "0")
		for _, raw := range anyList(orders["CertificateOrderList"]) {
			item := obj(raw)
			if strings.TrimLeft(strings.ToLower(text(item["SerialNo"])), "0") == serial {
				id = text(item["CertificateId"])
				if text(item["Name"]) != "" {
					name = text(item["Name"])
				}
				break
			}
		}
		if id == "" {
			uploaded, e := p.rpc(ctx, host, "2020-04-07", http.MethodPost, "UploadUserCertificate", map[string]string{"Name": name, "Cert": chain, "Key": key})
			if e != nil {
				return info, e
			}
			id = text(uploaded["CertId"])
			if id == "" {
				return info, errors.New("Aliyun CAS upload returned no certificate ID")
			}
		}
		info["cert_id"], info["cert_name"], info["certificate_fingerprint"], info["cert_region"] = id, name, fingerprint, region
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
	}
	if product == "upload" {
		return info, nil
	}
	if product == "esa" || product == "esa_saas" {
		return p.esaDeploy(ctx, id, name, region, cfg, target.Domains, info)
	}
	if product == "waf" || product == "wafres" || product == "waf2" {
		return p.wafDeploy(ctx, id, region, cfg, domains, info)
	}
	if product == "clb" || product == "alb" || product == "nlb" || product == "ga" {
		return p.loadBalancer(ctx, id, name, region, regionID, cfg, info)
	}
	return batch(ctx, domains, info, func(domain string) error {
		var host, version, action string
		params := map[string]string{}
		switch product {
		case "cdn", "dcdn", "live":
			host = product + ".aliyuncs.com"
			version = map[string]string{"cdn": "2018-05-10", "dcdn": "2018-01-15", "live": "2016-11-01"}[product]
			action = map[string]string{"cdn": "SetCdnDomainSSLCertificate", "dcdn": "SetDcdnDomainSSLCertificate", "live": "SetLiveDomainCertificate"}[product]
			params = map[string]string{"DomainName": domain, "CertName": name, "CertType": "cas", "SSLProtocol": "on", "CertId": id}
		case "ddoscoo":
			host = "ddoscoo." + region + ".aliyuncs.com"
			version = "2020-01-01"
			action = "AssociateWebCert"
			params = map[string]string{"Domain": domain, "CertId": id}
		case "oss":
			if e := aliyunRequire(cfg, "oss_endpoint", "oss_bucket"); e != nil {
				return e
			}
			return p.oss(ctx, cfg["oss_endpoint"], cfg["oss_bucket"], domain, id+"-"+region)
		}
		_, e := p.rpc(ctx, host, version, http.MethodPost, action, params)
		return e
	})
}
func (p *aliyunProvider) inlineDeploy(ctx context.Context, chain, key, name, product, region string, cfg map[string]string, domains []string, info Info) (Info, error) {
	if product == "api" {
		if e := aliyunRequire(cfg, "api_groupid"); e != nil {
			return info, e
		}
	}
	if product == "fc" || product == "fc2" {
		if e := aliyunRequire(cfg, "fc_cname"); e != nil {
			return info, e
		}
	}
	return batch(ctx, domains, info, func(domain string) error {
		switch product {
		case "api":
			_, e := p.rpc(ctx, "apigateway."+region+".aliyuncs.com", "2016-07-14", http.MethodPost, "SetDomainCertificate", map[string]string{"GroupId": cfg["api_groupid"], "DomainName": domain, "CertificateName": name, "CertificateBody": chain, "CertificatePrivateKey": key})
			return e
		case "vod":
			_, e := p.rpc(ctx, "vod.cn-shanghai.aliyuncs.com", "2017-03-21", http.MethodPost, "SetVodDomainCertificate", map[string]string{"DomainName": domain, "SSLProtocol": "on", "SSLPub": chain, "SSLPri": key})
			return e
		default:
			version := "2023-03-30"
			if product == "fc2" {
				version = "2021-04-06"
			}
			path := "/" + version + "/custom-domains/" + domain
			data, e := p.acs3(ctx, cfg["fc_cname"], version, http.MethodGet, "GetCustomDomain", path, nil)
			if e != nil {
				return e
			}
			certificate := obj(data["certConfig"])
			if certificate == nil {
				certificate = map[string]any{}
			}
			if text(certificate["certificate"]) == chain {
				return nil
			}
			certificate["certName"], certificate["certificate"], certificate["privateKey"] = name, chain, key
			body := map[string]any{"certConfig": certificate}
			for _, field := range []string{"protocol", "routeConfig", "tlsConfig", "wafConfig"} {
				if value, ok := data[field]; ok {
					body[field] = value
				}
			}
			if text(body["protocol"]) == "HTTP" {
				body["protocol"] = "HTTP,HTTPS"
			}
			if product == "fc" {
				if value, ok := data["authConfig"]; ok {
					body["authConfig"] = value
				}
			}
			_, e = p.acs3(ctx, cfg["fc_cname"], version, http.MethodPut, "UpdateCustomDomain", path, body)
			return e
		}
	})
}
