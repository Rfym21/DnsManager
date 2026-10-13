package deploy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type volcProvider struct{ *httpProvider }

func (p *volcProvider) call(ctx context.Context, endpoint, service, version, region, method, action string, body any) (map[string]any, error) {
	base := "https://" + endpoint
	if p.cfg["url"] != "" {
		base = p.base
	}
	query := url.Values{"Action": {action}, "Version": {version}}
	raw := []byte{}
	if method == http.MethodGet {
		for k, v := range obj(body) {
			query.Set(k, text(v))
		}
	} else if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	if service == "tos" {
		query = url.Values{"customdomain": {""}}
	}
	req, e := http.NewRequestWithContext(ctx, method, base+"/?"+strings.ReplaceAll(query.Encode(), "+", "%20"), bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	date := p.opts.Now().UTC().Format("20060102T150405Z")
	headers := map[string]string{"host": req.URL.Host, "x-date": date}
	algorithm := "HMAC-SHA256"
	if service == "tos" {
		delete(headers, "x-date")
		headers["x-tos-date"] = date
		headers["x-tos-content-sha256"] = sha256hex(raw)
		algorithm = "TOS4-HMAC-SHA256"
	}
	if len(raw) > 0 {
		headers["content-type"] = "application/json"
	}
	keys := []string{}
	for k, v := range headers {
		keys = append(keys, k)
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	sort.Strings(keys)
	canonicalHeaders := ""
	for _, k := range keys {
		canonicalHeaders += k + ":" + headers[k] + "\n"
	}
	signed := strings.Join(keys, ";")
	canonical := method + "\n/\n" + strings.ReplaceAll(query.Encode(), "+", "%20") + "\n" + canonicalHeaders + "\n" + signed + "\n" + sha256hex(raw)
	scope := date[:8] + "/" + region + "/" + service + "/request"
	sign := algorithm + "\n" + date + "\n" + scope + "\n" + sha256hex([]byte(canonical))
	key := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte(p.cfg["SecretAccessKey"]), date[:8]), region), service), "request")
	req.Header.Set("Authorization", algorithm+" Credential="+p.cfg["AccessKeyId"]+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(hmacSHA256(key, sign)))
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
		return nil, rejectedHTTP("huoshan", resp.StatusCode, "provider request failed")
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil, errors.New("invalid Volcengine JSON")
	}
	if err := obj(obj(m["ResponseMetadata"])["Error"]); len(err) > 0 {
		return nil, errors.New(safeError(err, p.cfg))
	}
	if v, ok := m["Result"]; ok {
		return obj(v), nil
	}
	return m, nil
}
func (p *volcProvider) Validate(ctx context.Context) error {
	if p.cfg["AccessKeyId"] == "" || p.cfg["SecretAccessKey"] == "" {
		return errors.New("Volcengine credentials are required")
	}
	_, e := p.call(ctx, "open.volcengineapi.com", "cdn", "2021-03-01", "cn-north-1", http.MethodPost, "ListCertInfo", map[string]any{"Source": "volc_cert_center"})
	return e
}
func (p *volcProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	info = renewedInfo(prior, sha256hex(leaf.Raw), "cert_id", "chain_id")
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	product := target.Config["product"]
	if product == "" {
		product = "cdn"
	}
	id := text(info["cert_id"])
	project := target.Config["project_name"]
	if product == "live" {
		id = text(info["chain_id"])
		if id == "" {
			body := map[string]any{"CertName": name, "Rsa": map[string]string{"Pubkey": chain, "Prikey": key}, "UseWay": "https"}
			if project != "" {
				body["ProjectName"] = project
			}
			v, e := p.call(ctx, "live.volcengineapi.com", "live", "2023-01-01", "cn-north-1", http.MethodPost, "CreateCert", body)
			if e != nil {
				return info, e
			}
			id = text(v["ChainID"])
			if id == "" {
				return info, errors.New("Volcengine live certificate ID unavailable")
			}
			info["chain_id"] = id
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
		}
	} else if id == "" {
		body := map[string]any{"Tag": name, "Repeatable": false, "CertificateInfo": map[string]string{"CertificateChain": chain, "PrivateKey": key}}
		if project != "" {
			body["ProjectName"] = project
		}
		v, e := p.call(ctx, "certificate-service.volcengineapi.com", "certificate_service", "2024-10-01", "cn-beijing", http.MethodPost, "ImportCertificate", body)
		if e != nil {
			return info, e
		}
		id = text(v["InstanceId"])
		if id == "" {
			id = text(v["RepeatId"])
		}
		if id == "" {
			return info, errors.New("Volcengine certificate ID unavailable")
		}
		info["cert_id"] = id
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
		if text(v["InstanceId"]) != "" {
			_, e = p.call(ctx, "certificate-service.volcengineapi.com", "certificate_service", "2024-10-01", "cn-beijing", http.MethodPost, "CertificateUpdateInstance", map[string]any{"InstanceId": id, "Options": map[string]string{"ExpiredNotice": "Disabled"}})
			if e != nil {
				return info, e
			}
		}
	}
	if product == "upload" {
		return info, nil
	}
	if product == "clb" || product == "alb" {
		listener := target.Config["listener_id"]
		if listener == "" {
			return info, errors.New("Volcengine listener ID is required")
		}
		_, e = p.call(ctx, "open.volcengineapi.com", product, "2020-04-01", "cn-beijing", http.MethodGet, "ModifyListenerAttributes", map[string]any{"ListenerId": listener, "CertificateSource": "cert_center", "CertCenterCertificateId": id})
		return info, e
	}
	domains := splitLines(strings.ReplaceAll(target.Config["domain"], ",", "\n"))
	return batch(ctx, domains, info, func(domain string) error {
		switch product {
		case "cdn":
			v, e := p.call(ctx, "cdn.volcengineapi.com", "cdn", "2021-03-01", "cn-north-1", http.MethodPost, "BatchDeployCert", map[string]any{"CertId": id, "Domain": domain})
			if e != nil {
				return e
			}
			rows := anyList(v["DeployResult"])
			if len(rows) != 1 || text(obj(rows[0])["Status"]) != "success" {
				return errors.New("Volcengine CDN certificate binding failed")
			}
			return nil
		case "dcdn":
			_, e := p.call(ctx, "open.volcengineapi.com", "dcdn", "2021-04-01", "cn-north-1", http.MethodPost, "CreateCertBind", map[string]any{"CertId": id, "DomainNames": []string{domain}})
			return e
		case "tos":
			bucket := target.Config["bucket_domain"]
			if bucket == "" {
				return errors.New("Volcengine TOS bucket domain is required")
			}
			_, e := p.call(ctx, bucket, "tos", "2021-04-01", "cn-beijing", http.MethodPut, "", map[string]any{"CustomDomainRule": map[string]string{"Domain": domain, "CertId": id}})
			return e
		case "live":
			_, e := p.call(ctx, "live.volcengineapi.com", "live", "2023-01-01", "cn-north-1", http.MethodPost, "BindCert", map[string]any{"ChainID": id, "Domain": domain, "HTTPS": true, "HTTP2": true})
			return e
		case "vod":
			space, kind := target.Config["vod_space_name"], target.Config["vod_domain_type"]
			if space == "" || kind == "" {
				return errors.New("Volcengine VOD space and domain type are required")
			}
			_, e := p.call(ctx, "vod.volcengineapi.com", "vod", "2023-07-01", "cn-north-1", http.MethodPost, "UpdateDomainConfig", map[string]any{"SpaceName": space, "DomainType": kind, "Domain": domain, "Config": map[string]any{"HTTPS": map[string]any{"Switch": true, "CertInfo": map[string]string{"CertId": id}}}})
			return e
		case "imagex":
			v, e := p.call(ctx, "imagex.volcengineapi.com", "imagex", "2018-08-01", "cn-north-1", http.MethodPost, "UpdateImageBatchDomainCert", []any{map[string]string{"domain": domain, "cert_id": id}})
			if e != nil {
				return e
			}
			if len(anyList(v["FailedDomains"])) > 0 || len(anyList(v["SuccessDomains"])) == 0 {
				return errors.New("Volcengine ImageX certificate binding failed")
			}
			return nil
		default:
			return errors.New("invalid Volcengine deployment product")
		}
	})
}
