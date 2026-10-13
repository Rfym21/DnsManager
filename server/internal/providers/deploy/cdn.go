package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type cdnProvider struct{ *httpProvider }

func (p *cdnProvider) headers(ctx context.Context) (map[string]string, error) {
	h := map[string]string{}
	switch p.kind {
	case "gcore":
		h["Authorization"] = "APIKey " + p.cfg["apikey"]
	case "cachefly":
		h["x-cf-authorization"] = "Bearer " + p.cfg["apikey"]
	case "axisnow":
		h["Authorization"] = "Bearer " + p.cfg["token"]
	case "rainyun":
		h["x-api-key"] = p.cfg["apikey"]
	case "cdnfly":
		if p.cfg["auth"] == "1" {
			v, e := p.json(ctx, http.MethodPost, "/v1/login", map[string]string{"account": p.cfg["username"], "password": p.cfg["password"]}, nil)
			if e != nil {
				return nil, e
			}
			if text(obj(v)["code"]) != "0" {
				return nil, errors.New(safeError(v, p.cfg))
			}
			token := text(obj(obj(v)["data"])["access_token"])
			if token == "" {
				return nil, errors.New("CDNFly login returned no token")
			}
			h["Access-Token"] = token
		} else {
			h["api-key"] = p.cfg["api_key"]
			h["api-secret"] = p.cfg["api_secret"]
		}
	case "lecdn":
		if p.cfg["auth"] == "1" {
			h["Authorization"] = p.cfg["api_key"]
		} else {
			v, e := p.json(ctx, http.MethodPost, "/prod-api/login", map[string]string{"email": p.cfg["email"], "username": p.cfg["email"], "password": p.cfg["password"]}, nil)
			if e != nil {
				return nil, e
			}
			if text(obj(v)["code"]) != "200" {
				return nil, errors.New(safeError(v, p.cfg))
			}
			token := text(obj(obj(v)["data"])["token"])
			if token == "" {
				return nil, errors.New("LeCDN login returned no token")
			}
			h["Authorization"] = "Bearer " + token
		}
	case "goedge":
		v, e := p.json(ctx, http.MethodPost, "/APIAccessTokenService/getAPIAccessToken", map[string]string{"type": p.cfg["usertype"], "accessKeyId": p.cfg["accessKeyId"], "accessKey": p.cfg["accessKey"]}, nil)
		if e != nil {
			return nil, e
		}
		token := text(obj(obj(v)["data"])["token"])
		if text(obj(v)["code"]) != "200" || token == "" {
			return nil, errors.New(safeError(v, p.cfg))
		}
		name := "X-Edge-Access-Token"
		if p.cfg["systype"] == "1" {
			name = "X-Cloud-Access-Token"
		}
		h[name] = token
	case "kuocai":
		v, e := p.form(ctx, "/login/loginUser", url.Values{"userAccount": {p.cfg["username"]}, "userPwd": {p.cfg["password"]}, "remember": {"true"}}, nil)
		if e != nil {
			return nil, e
		}
		if text(obj(v)["code"]) != "SUCCESS" {
			return nil, errors.New(safeError(v, p.cfg))
		}
		token := text(obj(v)["data"])
		if token == "" {
			return nil, errors.New("Kuocai login returned no token")
		}
		h["Cookie"] = "kuocai_cdn_token=" + token
	}
	return h, nil
}
func (p *cdnProvider) call(ctx context.Context, method, path string, body any, h map[string]string) (any, error) {
	v, e := p.json(ctx, method, path, body, h)
	if e != nil {
		return nil, e
	}
	m := obj(v)
	switch p.kind {
	case "gcore", "cachefly":
		return v, nil
	case "axisnow":
		if !truth(m["success"]) {
			return nil, errors.New(safeError(v, p.cfg))
		}
		return m["result"], nil
	case "cdnfly", "baishan":
		if text(m["code"]) != "0" {
			return nil, errors.New(safeError(v, p.cfg))
		}
		return m["data"], nil
	case "kuocai":
		if text(m["code"]) != "SUCCESS" {
			return nil, errors.New(safeError(v, p.cfg))
		}
		return m["data"], nil
	default:
		if text(m["code"]) != "200" {
			return nil, errors.New(safeError(v, p.cfg))
		}
		return m["data"], nil
	}
}
func (p *cdnProvider) Validate(ctx context.Context) error {
	h, e := p.headers(ctx)
	if e != nil {
		return e
	}
	if p.kind == "baishan" {
		if p.cfg["token"] == "" {
			return errors.New("Baishan token is required")
		}
		return nil
	}
	if p.kind == "goedge" || p.kind == "kuocai" {
		return nil
	}
	paths := map[string]string{"gcore": "/iam/clients/me", "cachefly": "/accounts/me", "axisnow": "/client/v1/certificates", "rainyun": "/product/", "cdnfly": "/v1/user", "lecdn": "/prod-api/system/info"}
	_, e = p.call(ctx, http.MethodGet, paths[p.kind], nil, h)
	return e
}
func certName(subject string, epoch int64) string {
	return strings.ReplaceAll(subject, "*.", "") + "-" + strconv.FormatInt(epoch, 10)
}
func (p *cdnProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	h, e := p.headers(ctx)
	if e != nil {
		return info, e
	}
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	id := target.Config["id"]
	if id == "" {
		id = text(info["certificate_id"])
	}
	switch p.kind {
	case "gcore":
		if id == "" {
			return info, errors.New("Gcore certificate ID is required")
		}
		_, e = p.call(ctx, http.MethodPut, "/cdn/sslData/"+url.PathEscape(id), map[string]any{"name": target.Config["name"], "sslCertificate": chain, "sslPrivateKey": key, "validate_root_ca": true}, h)
	case "cachefly":
		v, e := p.call(ctx, http.MethodPost, "/certificates", map[string]string{"certificate": chain, "certificateKey": key}, h)
		if e != nil {
			return info, e
		}
		if created := text(obj(v)["id"]); created != "" {
			info["certificate_id"] = created
			return info, persist(ctx, p.opts, info)
		}
		return info, nil
	case "axisnow":
		body := map[string]any{"name": name, "certificate": chain, "private_key": key}
		if id == "" {
			id = text(info["uuid"])
		}
		if id != "" {
			_, e = p.call(ctx, http.MethodPut, "/client/v1/certificates/"+url.PathEscape(id), body, h)
		} else {
			body["type"] = "upload"
			v, err := p.call(ctx, http.MethodPost, "/client/v1/certificates", body, h)
			if err != nil {
				return info, err
			}
			id = text(obj(v)["uuid"])
			if id == "" {
				return info, errors.New("AxisNow upload returned no UUID")
			}
			info["uuid"] = id
			return info, persist(ctx, p.opts, info)
		}
	case "baishan":
		if id == "" {
			return info, errors.New("Baishan certificate ID is required")
		}
		_, e = p.call(ctx, http.MethodPost, "/v2/domain/certificate?"+url.Values{"token": {p.cfg["token"]}}.Encode(), map[string]string{"cert_id": id, "name": name, "certificate": chain, "key": key}, h)
	case "kuocai":
		if id == "" {
			return info, errors.New("Kuocai domain ID is required")
		}
		_, e = p.call(ctx, http.MethodPost, "/CdnDomainHttps/httpsConfiguration", map[string]any{"doMainId": id, "https": map[string]string{"certificate_name": name, "certificate_source": "0", "certificate_value": chain, "https_status": "on", "private_key": key}}, h)
	case "cdnfly":
		body := map[string]string{"type": "custom", "cert": chain, "key": key}
		if id != "" {
			_, e = p.call(ctx, http.MethodPut, "/v1/certs/"+url.PathEscape(id), body, h)
		} else {
			body["name"] = name
			v, err := p.call(ctx, http.MethodPost, "/v1/certs", body, h)
			if err != nil {
				return info, err
			}
			id = text(v)
			if id == "" {
				id = text(obj(v)["id"])
			}
			if id == "" {
				return info, errors.New("CDNFly upload returned no certificate ID")
			}
			info["certificate_id"] = id
			return info, persist(ctx, p.opts, info)
		}
	case "lecdn":
		body := map[string]any{"type": "upload", "ssl_pem": base64.StdEncoding.EncodeToString([]byte(chain)), "ssl_key": base64.StdEncoding.EncodeToString([]byte(key)), "auto_renewal": false}
		if id != "" {
			v, err := p.call(ctx, http.MethodGet, "/prod-api/certificate/"+url.PathEscape(id), nil, h)
			if err != nil {
				return info, err
			}
			body["id"] = id
			body["name"] = text(obj(v)["name"])
			body["description"] = text(obj(v)["description"])
			_, e = p.call(ctx, http.MethodPut, "/prod-api/certificate/"+url.PathEscape(id), body, h)
		} else {
			body["name"] = name
			v, err := p.call(ctx, http.MethodPost, "/prod-api/certificate", body, h)
			if err != nil {
				return info, err
			}
			id = text(obj(v)["id"])
			if id == "" {
				return info, errors.New("LeCDN upload returned no certificate ID")
			}
			info["certificate_id"] = id
			return info, persist(ctx, p.opts, info)
		}
	case "rainyun":
		body := map[string]string{"cert": chain, "key": key}
		if id != "" {
			_, e = p.call(ctx, http.MethodPut, "/product/sslcenter/"+url.PathEscape(id), body, h)
		} else {
			v, err := p.call(ctx, http.MethodPost, "/product/sslcenter/", body, h)
			if err != nil {
				return info, err
			}
			id = text(obj(v)["ID"])
			if id == "" {
				id = text(obj(v)["id"])
			}
			if id == "" {
				value, err := p.call(ctx, http.MethodGet, "/product/sslcenter/?"+url.Values{"options": {`{"columnFilters":{"Domain":"` + leaf.Subject.CommonName + `"},"sort":[],"page":1,"perPage":100}`}}.Encode(), nil, h)
				if err != nil {
					return info, err
				}
				matches := []string{}
				for _, row := range anyList(obj(value)["Records"]) {
					m := obj(row)
					if text(m["Domain"]) == leaf.Subject.CommonName && text(m["Fingerprint"]) == sha256hex(leaf.Raw) {
						matches = append(matches, text(m["ID"]))
					}
				}
				if len(matches) != 1 {
					return info, errors.New("Rainyun upload returned no ID and cannot be identified unambiguously; select its certificate ID")
				}
				id = matches[0]
			}
			info["certificate_id"] = id
			return info, persist(ctx, p.opts, info)
		}
	case "goedge":
		if len(target.Domains) == 0 {
			return info, errors.New("deployment domains are required")
		}
		value, err := p.call(ctx, http.MethodPost, "/SSLCertService/listSSLCerts", map[string]any{"domains": target.Domains, "offset": 0, "size": 1000}, h)
		if err != nil {
			return info, err
		}
		raw, err := base64.StdEncoding.DecodeString(text(obj(value)["sslCertsJSON"]))
		if err != nil {
			return info, errors.New("invalid GoEdge certificate list")
		}
		var rows []map[string]any
		if err = json.Unmarshal(raw, &rows); err != nil {
			return info, err
		}
		if len(rows) >= 1000 {
			return info, errors.New("GoEdge certificate list exceeds limit")
		}
		body := map[string]any{"isOn": true, "name": name, "description": name, "serverName": leaf.Subject.CommonName, "isCA": false, "certData": base64.StdEncoding.EncodeToString([]byte(chain)), "keyData": base64.StdEncoding.EncodeToString([]byte(key)), "timeBeginAt": leaf.NotBefore.Unix(), "timeEndAt": leaf.NotAfter.Unix(), "dnsNames": target.Domains, "commonNames": []string{leaf.Issuer.CommonName}}
		if len(rows) == 0 {
			if id == "" {
				v, err := p.call(ctx, http.MethodPost, "/SSLCertService/createSSLCert", body, h)
				if err != nil {
					return info, err
				}
				id = text(obj(v)["sslCertId"])
				if id == "" {
					return info, errors.New("GoEdge creation returned no ID")
				}
				info["certificate_id"] = id
				return info, persist(ctx, p.opts, info)
			}
			rows = append(rows, map[string]any{"id": id, "name": name, "description": name, "serverName": leaf.Subject.CommonName})
		}
		ids := []string{}
		lookup := map[string]map[string]any{}
		for _, row := range rows {
			rid := text(row["id"])
			ids = append(ids, rid)
			lookup[rid] = row
		}
		return batch(ctx, ids, info, func(id string) error {
			b := map[string]any{}
			for k, v := range body {
				b[k] = v
			}
			b["sslCertId"] = id
			for _, k := range []string{"name", "description", "serverName"} {
				b[k] = lookup[id][k]
			}
			_, err := p.call(ctx, http.MethodPost, "/SSLCertService/updateSSLCert", b, h)
			return err
		})
	}
	return info, e
}

type dogeProvider struct{ *httpProvider }

func (p *dogeProvider) call(ctx context.Context, path string, values url.Values) (any, error) {
	body := ""
	if values != nil {
		body = values.Encode()
	}
	mac := hmac.New(sha1.New, []byte(p.cfg["SecretKey"]))
	mac.Write([]byte(path + "\n" + body))
	h := map[string]string{"Authorization": "TOKEN " + p.cfg["AccessKey"] + ":" + hex.EncodeToString(mac.Sum(nil)), "Content-Type": "application/x-www-form-urlencoded"}
	method := http.MethodGet
	if values != nil {
		method = http.MethodPost
	}
	v, e := p.request(ctx, method, path, []byte(body), h)
	if e != nil {
		return nil, e
	}
	if text(obj(v)["code"]) != "200" {
		return nil, errors.New(safeError(v, p.cfg))
	}
	return obj(v)["data"], nil
}
func (p *dogeProvider) Validate(ctx context.Context) error {
	if p.cfg["AccessKey"] == "" || p.cfg["SecretKey"] == "" {
		return errors.New("Doge credentials are required")
	}
	_, e := p.call(ctx, "/cdn/cert/list.json", nil)
	return e
}
func (p *dogeProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	id := text(info["cert_id"])
	if id == "" {
		v, err := p.call(ctx, "/cdn/cert/list.json", nil)
		if err != nil {
			return info, err
		}
		for _, row := range anyList(obj(v)["certs"]) {
			m := obj(row)
			if text(m["note"]) == name {
				id = text(m["id"])
				break
			}
		}
	}
	if id == "" {
		v, err := p.call(ctx, "/cdn/cert/upload.json", url.Values{"note": {name}, "cert": {chain}, "private": {key}})
		if err != nil {
			return info, err
		}
		id = text(obj(v)["id"])
		if id == "" {
			return info, errors.New("Doge upload returned no certificate ID")
		}
		info["cert_id"] = id
		if err = persist(ctx, p.opts, info); err != nil {
			return info, err
		}
	}
	return batch(ctx, strings.Split(target.Config["domain"], ","), info, func(domain string) error {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return errors.New("domain is required")
		}
		_, err := p.call(ctx, "/cdn/cert/bind.json", url.Values{"id": {id}, "domain": {domain}})
		return err
	})
}
