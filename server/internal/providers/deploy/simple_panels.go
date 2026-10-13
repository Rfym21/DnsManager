package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type simplePanelProvider struct{ *httpProvider }

func (p *simplePanelProvider) call(ctx context.Context, method, path string, body any, node string) (any, error) {
	headers := map[string]string{}
	switch p.kind {
	case "xp":
		headers["XP-API-KEY"] = p.cfg["apikey"]
	case "lucky":
		headers["openToken"] = p.cfg["opentoken"]
	case "safeline":
		headers["X-SLCE-API-TOKEN"] = p.cfg["token"]
	case "opanel":
		version := p.cfg["version"]
		if version == "" {
			version = "v1"
		}
		if version != "v1" && version != "v2" {
			return nil, errors.New("invalid 1Panel API version")
		}
		path = "/api/" + version + path
		timestamp := strconv.FormatInt(p.opts.Now().Unix(), 10)
		headers["1Panel-Token"] = md5hex("1panel" + p.cfg["key"] + timestamp)
		headers["1Panel-Timestamp"] = timestamp
		if node != "" {
			headers["CurrentNode"] = node
		}
		if body == nil {
			body = map[string]any{}
		}
	}
	value, err := p.json(ctx, method, path, body, headers)
	if err != nil {
		return nil, err
	}
	m := obj(value)
	switch p.kind {
	case "xp":
		if text(m["code"]) != "1000" {
			return nil, errors.New(safeError(value, p.cfg))
		}
		return m["data"], nil
	case "lucky":
		if text(m["ret"]) != "0" {
			return nil, errors.New(safeError(value, p.cfg))
		}
		return m, nil
	case "safeline":
		if _, ok := m["data"]; !ok {
			return nil, errors.New(safeError(value, p.cfg))
		}
		return m["data"], nil
	case "opanel":
		if text(m["code"]) != "200" {
			return nil, errors.New(safeError(value, p.cfg))
		}
		return m["data"], nil
	}
	return value, nil
}
func (p *simplePanelProvider) Validate(ctx context.Context) error {
	path := map[string]string{"xp": "/openApi/siteList", "lucky": "/api/modules/list", "safeline": "/api/open/system", "opanel": "/settings/search"}[p.kind]
	method := http.MethodGet
	if p.kind == "opanel" {
		method = http.MethodPost
	}
	_, err := p.call(ctx, method, path, nil, "")
	return err
}
func anyList(v any) []any {
	switch list := v.(type) {
	case []any:
		return list
	case []string:
		out := make([]any, len(list))
		for i, item := range list {
			out[i] = item
		}
		return out
	}
	return nil
}
func matchesDomains(actual []string, wanted []string) bool {
	for _, a := range actual {
		for _, w := range wanted {
			if domainMatches(w, a) || domainMatches(a, w) {
				return true
			}
		}
	}
	return false
}
func stringList(v any) []string {
	r := []string{}
	for _, x := range anyList(v) {
		if s := text(x); s != "" {
			r = append(r, s)
		}
	}
	return r
}
func (p *simplePanelProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, err := parsePair(chain, key); err != nil {
		return info, err
	}
	switch p.kind {
	case "xp":
		value, err := p.call(ctx, http.MethodGet, "/openApi/siteList", nil, "")
		if err != nil {
			return info, err
		}
		sites := map[string]string{}
		for _, v := range anyList(value) {
			m := obj(v)
			sites[text(m["name"])] = text(m["id"])
		}
		return batch(ctx, splitLines(target.Config["sites"]), info, func(site string) error {
			id := sites[site]
			if id == "" {
				return errors.New("website not found")
			}
			_, err := p.call(ctx, http.MethodPost, "/openApi/setSSL", map[string]any{"id": id, "key": key, "pem": chain}, "")
			return err
		})
	case "lucky":
		if len(target.Domains) == 0 {
			return info, errors.New("deployment domains are required")
		}
		value, err := p.call(ctx, http.MethodGet, "/api/ssl", nil, "")
		if err != nil {
			return info, err
		}
		rows := map[string]map[string]any{}
		ids := []string{}
		for _, v := range anyList(obj(value)["list"]) {
			m := obj(v)
			if matchesDomains(stringList(obj(m["CertsInfo"])["Domains"]), target.Domains) {
				id := text(m["Key"])
				ids = append(ids, id)
				rows[id] = m
			}
		}
		return batch(ctx, ids, info, func(id string) error {
			m := rows[id]
			_, err := p.call(ctx, http.MethodPut, "/api/ssl", map[string]any{"Key": id, "CertBase64": base64.StdEncoding.EncodeToString([]byte(chain)), "KeyBase64": base64.StdEncoding.EncodeToString([]byte(key)), "AddFrom": "file", "Enable": true, "MappingToPath": false, "Remark": text(m["Remark"]), "AllSyncClient": false}, "")
			return err
		})
	case "safeline":
		if len(target.Domains) == 0 {
			return info, errors.New("deployment domains are required")
		}
		value, err := p.call(ctx, http.MethodGet, "/api/open/cert", nil, "")
		if err != nil {
			return info, err
		}
		ids := []string{}
		for _, v := range anyList(obj(value)["nodes"]) {
			m := obj(v)
			if matchesDomains(stringList(m["domains"]), target.Domains) {
				ids = append(ids, text(m["id"]))
			}
		}
		if len(ids) == 0 {
			if id := text(info["certificate_id"]); id != "" {
				ids = append(ids, id)
			} else {
				v, err := p.call(ctx, http.MethodPost, "/api/open/cert", map[string]any{"manual": map[string]string{"crt": chain, "key": key}, "type": 2}, "")
				if err != nil {
					return info, err
				}
				id := text(obj(v)["id"])
				if id == "" {
					return info, errors.New("SafeLine certificate creation returned no ID")
				}
				info["certificate_id"] = id
				return info, persist(ctx, p.opts, info)
			}
		}
		return batch(ctx, ids, info, func(id string) error {
			_, err := p.call(ctx, http.MethodPost, "/api/open/cert", map[string]any{"id": id, "manual": map[string]string{"crt": chain, "key": key}, "type": 2}, "")
			return err
		})
	case "opanel":
		nodes := append([]string{""}, splitLines(target.Config["node_name"])...)
		labels := []string{}
		for _, node := range nodes {
			if node == "" {
				labels = append(labels, "main")
			} else {
				labels = append(labels, node)
			}
		}
		return batch(ctx, labels, info, func(label string) error {
			node := label
			if label == "main" {
				node = ""
			}
			if target.Config["type"] == "3" {
				_, err := p.call(ctx, http.MethodPost, "/core/settings/ssl/update", map[string]any{"cert": chain, "key": key, "ssl": "Enable", "sslID": nil, "sslType": "import-paste"}, node)
				return err
			}
			ids := []string{}
			if id := target.Config["id"]; id != "" {
				ids = append(ids, id)
			} else {
				if len(target.Domains) == 0 {
					return errors.New("deployment domains are required")
				}
				value, err := p.call(ctx, http.MethodPost, "/websites/ssl/search", map[string]any{"page": 1, "pageSize": 500, "orderBy": "expire_date", "order": "null"}, node)
				if err != nil {
					return err
				}
				if n, _ := strconv.Atoi(text(obj(value)["total"])); n > 500 {
					return errors.New("1Panel certificate list exceeds page size; select an explicit certificate ID")
				}
				for _, v := range anyList(obj(value)["items"]) {
					m := obj(v)
					domains := append([]string{text(m["primaryDomain"])}, strings.Split(text(m["domains"]), ",")...)
					if matchesDomains(domains, target.Domains) {
						ids = append(ids, text(m["id"]))
					}
				}
			}
			if len(ids) == 0 {
				if id := text(obj(info["node_certificates"])[label]); id != "" {
					ids = append(ids, id)
				} else {
					ids = append(ids, "0")
				}
			}
			for _, id := range ids {
				number, err := strconv.Atoi(id)
				if err != nil {
					return errors.New("invalid certificate ID")
				}
				value, err := p.call(ctx, http.MethodPost, "/websites/ssl/upload", map[string]any{"sslID": number, "type": "paste", "certificate": chain, "privateKey": key, "description": ""}, node)
				if err != nil {
					return err
				}
				if id == "0" {
					created := text(obj(value)["id"])
					if created == "" {
						created = text(value)
					}
					if created == "" {
						return errors.New("1Panel upload returned no certificate ID")
					}
					m := obj(info["node_certificates"])
					if m == nil {
						m = map[string]any{}
					}
					m[label] = created
					info["node_certificates"] = m
					if err = persist(ctx, p.opts, info); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	return info, errors.New("unknown panel provider")
}

type proxmoxProvider struct{ *httpProvider }

func (p *proxmoxProvider) call(ctx context.Context, path string, values url.Values) (any, error) {
	headers := map[string]string{"Authorization": "PVEAPIToken=" + p.cfg["api_user"] + "=" + p.cfg["api_key"]}
	var v any
	var err error
	if values == nil {
		v, err = p.request(ctx, http.MethodGet, path, nil, headers)
	} else {
		v, err = p.form(ctx, path, values, headers)
	}
	if err != nil {
		return nil, err
	}
	m := obj(v)
	if value, ok := m["data"]; ok {
		return value, nil
	}
	return nil, errors.New(safeError(v, p.cfg))
}
func (p *proxmoxProvider) Validate(ctx context.Context) error {
	if p.cfg["api_user"] == "" || p.cfg["api_key"] == "" {
		return errors.New("Proxmox API token is required")
	}
	_, err := p.call(ctx, "/api2/json/access", nil)
	return err
}
func (p *proxmoxProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, err := parsePair(chain, key)
	if err != nil {
		return info, err
	}
	node := target.Config["node"]
	if node == "" {
		return info, errors.New("Proxmox node is required")
	}
	path := "/api2/json/nodes/" + url.PathEscape(node) + "/certificates/"
	value, err := p.call(ctx, path+"info", nil)
	if err != nil {
		return info, err
	}
	fingerprint := sha256hex(leaf.Raw)
	for _, v := range anyList(value) {
		if strings.ToLower(strings.ReplaceAll(text(obj(v)["fingerprint"]), ":", "")) == fingerprint {
			info["fingerprint"] = fingerprint
			return info, nil
		}
	}
	_, err = p.call(ctx, path+"custom", url.Values{"certificates": {chain}, "key": {key}, "force": {"1"}, "restart": {"1"}})
	info["fingerprint"] = fingerprint
	return info, err
}

type directadminProvider struct{ *httpProvider }

func (p *directadminProvider) call(ctx context.Context, method, path string, values url.Values) error {
	var body []byte
	if values != nil {
		body = []byte(values.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.SetBasicAuth(p.cfg["username"], p.cfg["password"])
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return rejectedHTTP("directadmin", resp.StatusCode, "provider request failed")
	}
	raw, err := readLimited(resp.Body)
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		var result map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if decoder.Decode(&result) != nil {
			return errors.New("invalid DirectAdmin JSON response")
		}
		failure, exists := result["error"]
		if !exists || !(failure == false || text(failure) == "0" || text(failure) == "false") {
			return errors.New(safeError(map[string]any{"msg": result["details"]}, p.cfg))
		}
		return nil
	}
	data, err := url.ParseQuery(string(raw))
	if err != nil {
		return errors.New("invalid DirectAdmin response")
	}
	if data.Get("error") != "0" {
		return errors.New(safeError(map[string]any{"msg": data.Get("details")}, p.cfg))
	}
	return nil
}
func (p *directadminProvider) validateConfig() error {
	u, _ := url.Parse(p.base)
	if u.Scheme != "https" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("DirectAdmin requires an HTTPS origin URL")
	}
	if p.cfg["username"] == "" || p.cfg["password"] == "" {
		return errors.New("DirectAdmin authentication is required")
	}
	return nil
}
func (p *directadminProvider) Validate(ctx context.Context) error {
	if err := p.validateConfig(); err != nil {
		return err
	}
	return p.call(ctx, http.MethodGet, "/CMD_API_LOGIN_TEST", nil)
}
func (p *directadminProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if err := p.validateConfig(); err != nil {
		return info, err
	}
	_, _, private, err := parsePair(chain, key)
	if err != nil {
		return info, err
	}
	if ec, ok := private.(*ecdsa.PrivateKey); ok {
		der, e := x509.MarshalECPrivateKey(ec)
		if e != nil {
			return info, e
		}
		key = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}
	domains := strings.FieldsFunc(target.Config["domain"], func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' })
	return batch(ctx, domains, info, func(domain string) error {
		if domain == "" || strings.ContainsAny(domain, "/\\:*?@") {
			return errors.New("invalid DirectAdmin domain")
		}
		return p.call(ctx, http.MethodPost, "/CMD_API_SSL", url.Values{"domain": {domain}, "action": {"save"}, "type": {"paste"}, "certificate": {strings.TrimRight(key, "\n") + "\n" + strings.TrimSpace(chain) + "\n"}})
	})
}

type uusecProvider struct{ *httpProvider }

func (p *uusecProvider) login(ctx context.Context) (string, error) {
	if p.cfg["username"] == "" || p.cfg["password"] == "" {
		return "", errors.New("UUSEC username and password are required")
	}
	v, err := p.json(ctx, http.MethodPost, "/api/v1/users/login", map[string]string{"usr": p.cfg["username"], "pwd": p.cfg["password"], "otp": ""}, nil)
	if err != nil {
		return "", err
	}
	token := text(obj(v)["token"])
	if token == "" {
		return "", errors.New(safeError(v, p.cfg))
	}
	return token, nil
}
func (p *uusecProvider) Validate(ctx context.Context) error { _, err := p.login(ctx); return err }
func (p *uusecProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, err := parsePair(chain, key); err != nil {
		return info, err
	}
	id, err := strconv.Atoi(target.Config["id"])
	if err != nil || id <= 0 {
		return info, errors.New("valid UUSEC certificate ID is required")
	}
	token, err := p.login(ctx)
	if err != nil {
		return info, err
	}
	v, err := p.json(ctx, http.MethodPut, "/api/v1/certs", map[string]any{"id": id, "type": 1, "name": target.Config["name"], "crt": chain, "key": key}, map[string]string{"Authorization": "Bearer " + token})
	if err != nil {
		return info, err
	}
	if text(v) != "OK" {
		return info, errors.New(safeError(v, p.cfg))
	}
	return info, nil
}
