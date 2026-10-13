package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type regionalCloudProvider struct{ *httpProvider }

func (p *regionalCloudProvider) call(ctx context.Context, endpoint, method, path string, body any) (map[string]any, error) {
	if p.cfg["url"] != "" {
		endpoint = p.base
	} else {
		endpoint = "https://" + endpoint
	}
	raw := []byte{}
	if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	now := p.opts.Now().UTC()
	headers := map[string]string{"host": req.URL.Host}
	if body != nil {
		headers["content-type"] = "application/json"
	}
	dateHeader, date := "x-sdk-date", now.Format("20060102T150405Z")
	if p.kind == "baidu" {
		dateHeader = "x-bce-date"
		date = now.Format("2006-01-02T15:04:05Z")
	}
	headers[dateHeader] = date
	keys := []string{}
	for k := range headers {
		keys = append(keys, k)
		if k != "host" {
			req.Header.Set(k, headers[k])
		}
	}
	sort.Strings(keys)
	canonicalHeaders := ""
	for _, k := range keys {
		if p.kind == "baidu" {
			canonicalHeaders += awsEscape(k) + ":" + awsEscape(headers[k]) + "\n"
		} else {
			canonicalHeaders += k + ":" + headers[k] + "\n"
		}
	}
	query := strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20")
	uri := req.URL.EscapedPath()
	if p.kind == "huawei" {
		if !strings.HasSuffix(uri, "/") {
			uri += "/"
		}
		canonical := method + "\n" + uri + "\n" + query + "\n" + canonicalHeaders + "\n" + strings.Join(keys, ";") + "\n" + sha256hex(raw)
		sign := "SDK-HMAC-SHA256\n" + date + "\n" + sha256hex([]byte(canonical))
		req.Header.Set("Authorization", "SDK-HMAC-SHA256 Access="+p.cfg["AccessKeyId"]+", SignedHeaders="+strings.Join(keys, ";")+", Signature="+hex.EncodeToString(hmacSHA256([]byte(p.cfg["SecretAccessKey"]), sign)))
	} else {
		auth := "bce-auth-v1/" + p.cfg["AccessKeyId"] + "/" + date + "/1800"
		signKey := hex.EncodeToString(hmacSHA256([]byte(p.cfg["SecretAccessKey"]), auth))
		canonical := method + "\n" + uri + "\n" + query + "\n" + strings.TrimSuffix(canonicalHeaders, "\n")
		req.Header.Set("Authorization", auth+"/"+strings.Join(keys, ";")+"/"+hex.EncodeToString(hmacSHA256([]byte(signKey), canonical)))
	}
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
		return nil, rejectedHTTP(p.kind, resp.StatusCode, "provider request failed")
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil, errors.New("invalid cloud JSON response")
	}
	if m["error_msg"] != nil || m["error"] != nil || m["code"] != nil && m["message"] != nil {
		return nil, errors.New(safeError(m, p.cfg))
	}
	return m, nil
}
func (p *regionalCloudProvider) Validate(ctx context.Context) error {
	if p.cfg["AccessKeyId"] == "" || p.cfg["SecretAccessKey"] == "" {
		return errors.New("cloud access credentials are required")
	}
	endpoint, path := "scm.cn-north-4.myhuaweicloud.com", "/v3/scm/certificates"
	if p.kind == "baidu" {
		endpoint = "cdn.baidubce.com"
		path = "/v2/domain"
	}
	_, e := p.call(ctx, endpoint, http.MethodGet, path, nil)
	return e
}
func (p *regionalCloudProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	info = renewedInfo(prior, sha256hex(leaf.Raw), "cert_id")
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	product := target.Config["product"]
	if p.kind == "huawei" {
		switch product {
		case "cdn":
			return batch(ctx, splitLines(strings.ReplaceAll(target.Config["domain"], ",", "\n")), info, func(domain string) error {
				_, e := p.call(ctx, "cdn.myhuaweicloud.com", http.MethodPut, "/v1.1/cdn/configuration/domains/"+url.PathEscape(domain)+"/configs", map[string]any{"configs": map[string]any{"https": map[string]any{"https_status": "on", "certificate_type": "server", "certificate_source": 0, "certificate_name": name, "certificate_value": chain, "private_key": key}}})
				return e
			})
		case "elb", "waf":
			region, project, id := target.Config["region_id"], target.Config["project_id"], target.Config["cert_id"]
			if region == "" || project == "" || id == "" {
				return info, errors.New("Huawei region, project and certificate IDs are required")
			}
			endpoint := product + "." + region + ".myhuaweicloud.com"
			path := "/v3/" + url.PathEscape(project) + "/elb/certificates/" + url.PathEscape(id)
			body := map[string]any{"certificate": map[string]any{"certificate": chain, "private_key": key, "domain": strings.Join(target.Domains, ",")}}
			if product == "waf" {
				path = "/v1/" + url.PathEscape(project) + "/waf/certificates/" + url.PathEscape(id)
				body = map[string]any{"name": name, "content": chain, "key": key}
			}
			_, e = p.call(ctx, endpoint, http.MethodPut, path, body)
			return info, e
		case "upload":
			v, e := p.call(ctx, "scm.cn-north-4.myhuaweicloud.com", http.MethodPost, "/v3/scm/certificates/import", map[string]any{"name": name, "certificate": chain, "private_key": key})
			if e != nil {
				return info, e
			}
			id := text(v["certificate_id"])
			if id == "" {
				return info, errors.New("Huawei upload returned no certificate ID")
			}
			info["cert_id"] = id
			return info, persist(ctx, p.opts, info)
		case "obs":
			bucket, endpoint := target.Config["obs_bucket"], target.Config["obs_endpoint"]
			if bucket == "" || endpoint == "" {
				return info, errors.New("Huawei OBS bucket and endpoint are required")
			}
			return batch(ctx, splitLines(strings.ReplaceAll(target.Config["domain"], ",", "\n")), info, func(domain string) error {
				payload := struct {
					XMLName     xml.Name `xml:"CustomDomainConfiguration"`
					Name        string   `xml:"Name"`
					Certificate string   `xml:"Certificate"`
					PrivateKey  string   `xml:"PrivateKey"`
				}{Name: name, Certificate: chain, PrivateKey: key}
				raw, e := xml.Marshal(payload)
				if e != nil {
					return e
				}
				base := "https://" + bucket + "." + strings.TrimPrefix(endpoint, "https://")
				if p.cfg["url"] != "" {
					base = p.base
				}
				req, e := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimRight(base, "/")+"/?"+url.Values{"customdomain": {domain}}.Encode(), bytes.NewReader(raw))
				if e != nil {
					return e
				}
				hash := md5.Sum(raw)
				contentMD5 := base64.StdEncoding.EncodeToString(hash[:])
				date := p.opts.Now().UTC().Format(http.TimeFormat)
				sign := "PUT\n" + contentMD5 + "\napplication/xml\n" + date + "\n/" + bucket + "/?customdomain=" + domain
				mac := hmac.New(sha1.New, []byte(p.cfg["SecretAccessKey"]))
				mac.Write([]byte(sign))
				req.Header.Set("Content-Type", "application/xml")
				req.Header.Set("Content-MD5", contentMD5)
				req.Header.Set("Date", date)
				req.Header.Set("Authorization", "OBS "+p.cfg["AccessKeyId"]+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
				resp, e := p.client.Do(req)
				if e != nil {
					return e
				}
				defer resp.Body.Close()
				if resp.StatusCode/100 != 2 {
					return rejectedHTTP("huawei", resp.StatusCode, "OBS request failed")
				}
				return nil
			})
		default:
			return info, errors.New("invalid Huawei product")
		}
	}
	if product == "" || product == "cdn" {
		return batch(ctx, splitLines(strings.ReplaceAll(target.Config["domain"], ",", "\n")), info, func(domain string) error {
			v, e := p.call(ctx, "cdn.baidubce.com", http.MethodPut, "/v2/"+url.PathEscape(domain)+"/certificates", map[string]any{"httpsEnable": "ON", "certificate": map[string]any{"certName": name, "certServerData": chain, "certPrivateData": key}})
			if e == nil {
				info["cert_id"] = text(v["certId"])
			}
			return e
		})
	}
	id := text(info["cert_id"])
	if id == "" {
		v, e := p.call(ctx, "certificate.baidubce.com", http.MethodGet, "/v1/certificate?"+url.Values{"certName": {name}}.Encode(), nil)
		if e != nil {
			return info, e
		}
		for _, row := range anyList(v["certs"]) {
			m := obj(row)
			if text(m["certName"]) == name {
				id = text(m["certId"])
				break
			}
		}
	}
	if id == "" {
		v, e := p.call(ctx, "certificate.baidubce.com", http.MethodPost, "/v1/certificate", map[string]any{"certName": name, "certServerData": chain, "certPrivateData": key})
		if e != nil {
			return info, e
		}
		id = text(v["certId"])
		if id == "" {
			return info, errors.New("Baidu upload returned no certificate ID")
		}
		info["cert_id"] = id
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
	}
	if product == "upload" {
		return info, nil
	}
	if product != "blb" && product != "appblb" {
		return info, errors.New("invalid Baidu product")
	}
	resource, region := target.Config["blb_id"], target.Config["region"]
	port, e := strconv.Atoi(target.Config["blb_port"])
	if resource == "" || region == "" || e != nil || port < 1 || port > 65535 {
		return info, errors.New("Baidu load balancer, region and listener port are required")
	}
	_, e = p.call(ctx, "blb."+region+".baidubce.com", http.MethodPut, "/v1/"+product+"/"+url.PathEscape(resource)+"/HTTPSlistener?"+url.Values{"listenerPort": {strconv.Itoa(port)}}.Encode(), map[string]any{"certIds": []string{id}})
	return info, e
}
