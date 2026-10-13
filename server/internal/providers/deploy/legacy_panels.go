package deploy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type pageResponse struct {
	code     int
	body     string
	location string
}

func (p *httpProvider) page(ctx context.Context, method, path string, values url.Values, headers map[string]string) (pageResponse, error) {
	var data []byte
	if values != nil {
		data = []byte(values.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, bytes.NewReader(data))
	if err != nil {
		return pageResponse{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if values != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return pageResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := readLimited(resp.Body)
	if err != nil {
		return pageResponse{}, err
	}
	if resp.StatusCode >= 400 {
		return pageResponse{}, rejectedHTTP(p.kind, resp.StatusCode, "provider request failed")
	}
	return pageResponse{resp.StatusCode, string(raw), resp.Header.Get("Location")}, nil
}
func newSession(p *httpProvider) *httpProvider {
	copy := *p
	client := *p.client
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	copy.client = &client
	return &copy
}
func (p *httpProvider) sessionCookie() bool {
	u, _ := url.Parse(p.base)
	return p.client.Jar != nil && len(p.client.Jar.Cookies(u)) > 0
}
func extractInput(source, name string) string {
	tags := regexp.MustCompile(`(?is)<input\b[^>]*>`).FindAllString(source, -1)
	attr := regexp.MustCompile(`(?i)(name|id|value)\s*=\s*["']([^"']*)["']`)
	for _, tag := range tags {
		values := map[string]string{}
		for _, m := range attr.FindAllStringSubmatch(tag, -1) {
			values[strings.ToLower(m[1])] = html.UnescapeString(m[2])
		}
		if values["name"] == name || values["id"] == name {
			return values["value"]
		}
	}
	return ""
}

type legacyPanelProvider struct{ *httpProvider }

func (p *legacyPanelProvider) login(ctx context.Context) (*httpProvider, error) {
	q := newSession(p.httpProvider)
	switch p.kind {
	case "cloudpanel":
		page, e := q.page(ctx, http.MethodGet, "/login", nil, nil)
		if e != nil {
			return nil, e
		}
		token := extractInput(page.body, "_csrf_token")
		if page.code != 200 || token == "" {
			return nil, errors.New("CloudPanel CSRF token unavailable")
		}
		res, e := q.page(ctx, http.MethodPost, "/login", url.Values{"userName": {p.cfg["username"]}, "password": {p.cfg["password"]}, "_csrf_token": {token}}, map[string]string{"Origin": p.base, "Referer": p.base + "/login"})
		if e != nil {
			return nil, e
		}
		if strings.Contains(strings.ToLower(res.location+res.body), "two_factor") || strings.Contains(strings.ToLower(res.location), "2fa") {
			return nil, errors.New("CloudPanel two-factor login requires an API-capable account")
		}
		if res.code/100 != 3 || !q.sessionCookie() || strings.Contains(res.location, "login") {
			return nil, errors.New("CloudPanel login failed")
		}
		return q, nil
	case "amh":
		payload := "amapi_expires=" + strconv.FormatInt(p.opts.Now().Unix()+120, 10)
		mac := hmac.New(sha256.New, []byte(p.cfg["apikey"]))
		mac.Write([]byte(payload))
		session := hmac.New(md5.New, []byte(p.cfg["apikey"]))
		session.Write([]byte("php_sessid=" + p.cfg["apikey"]))
		values, _ := url.ParseQuery(payload)
		values.Set("amapi_sign", hex.EncodeToString(mac.Sum(nil)))
		res, e := q.page(ctx, http.MethodPost, "/?c=amapi&a=login", values, map[string]string{"Cookie": "PHPSESSID=" + hex.EncodeToString(session.Sum(nil))})
		if e != nil {
			return nil, e
		}
		location, _ := url.Parse(res.location)
		if res.code != 302 || location.Query().Get("amh_token") == "" {
			return nil, errors.New("AMH login failed")
		}
		q.cfg = map[string]string{}
		for k, v := range p.cfg {
			q.cfg[k] = v
		}
		q.cfg["amh_token"] = location.Query().Get("amh_token")
		q.cfg["session_cookie"] = "PHPSESSID=" + hex.EncodeToString(session.Sum(nil))
		return q, nil
	case "kangle", "kangleadmin":
		base := "/vhost"
		if p.kind == "kangleadmin" {
			base = strings.TrimRight(p.cfg["path"], "/")
			if base == "" {
				base = "/admin"
			}
		}
		if p.kind == "kangle" && p.cfg["auth"] != "1" {
			res, e := q.page(ctx, http.MethodPost, "/vhost/index.php?c=session&a=login", url.Values{"username": {p.cfg["username"]}, "passwd": {p.cfg["password"]}}, nil)
			if e != nil {
				return nil, e
			}
			if res.code != 302 || !q.sessionCookie() {
				return nil, errors.New("Kangle password login failed")
			}
			return q, nil
		}
		res, e := q.page(ctx, http.MethodGet, base+"/index.php?c=sso&a=hello&"+url.Values{"url": {p.base + base + "/index.php?"}}.Encode(), nil, nil)
		if e != nil {
			return nil, e
		}
		location, _ := url.Parse(res.location)
		session := location.Query().Get("r")
		if res.code != 302 || session == "" || !q.sessionCookie() {
			return nil, errors.New("Kangle SSO session unavailable")
		}
		query := url.Values{"c": {"sso"}, "a": {"login"}, "name": {p.cfg["username"]}, "r": {session}, "s": {md5hex(session + p.cfg["username"] + session + p.cfg["skey"])}}
		res, e = q.page(ctx, http.MethodGet, base+"/index.php?"+query.Encode(), nil, nil)
		if e != nil {
			return nil, e
		}
		if res.code != 302 {
			return nil, errors.New("Kangle SSO authentication failed")
		}
		return q, nil
	case "upyun":
		v, e := q.form(ctx, "/accounts/signin/", url.Values{"username": {p.cfg["username"]}, "password": {p.cfg["password"]}}, nil)
		if e != nil {
			return nil, e
		}
		if !truth(obj(obj(v)["data"])["result"]) || !q.sessionCookie() {
			return nil, errors.New("Upyun login failed")
		}
		return q, nil
	}
	return nil, errors.New("unknown session protocol")
}
func (p *legacyPanelProvider) Validate(ctx context.Context) error { _, e := p.login(ctx); return e }
func (p *legacyPanelProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, private, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	q, e := p.login(ctx)
	if e != nil {
		return info, e
	}
	switch p.kind {
	case "cloudpanel":
		sites := strings.FieldsFunc(target.Config["sites"], func(r rune) bool { return r == '\r' || r == '\n' || r == ',' })
		return batch(ctx, sites, info, func(site string) error {
			site = strings.TrimSpace(site)
			path := "/site/" + url.PathEscape(site) + "/certificate/import"
			page, e := q.page(ctx, http.MethodGet, path, nil, nil)
			if e != nil {
				return e
			}
			token := extractInput(page.body, "site_import_certificate[_token]")
			if token == "" {
				token = extractInput(page.body, "site_import_certificate__token")
			}
			if page.code != 200 || token == "" {
				return errors.New("CloudPanel certificate import token unavailable")
			}
			res, e := q.page(ctx, http.MethodPost, path, url.Values{"site_import_certificate[privateKey]": {key}, "site_import_certificate[certificate]": {chain}, "site_import_certificate[certificateChain]": {""}, "site_import_certificate[submit]": {"Import and Install"}, "site_import_certificate[_token]": {token}}, map[string]string{"Origin": p.base, "Referer": p.base + path})
			if e != nil {
				return e
			}
			if res.code/100 == 3 && !strings.Contains(res.location, "login") && (strings.Contains(res.location, "/certificates") || strings.Contains(res.location, "/site/"+site)) {
				return nil
			}
			return errors.New("CloudPanel certificate import failed")
		})
	case "amh":
		if target.Config["env_name"] == "" {
			return info, errors.New("AMH environment is required")
		}
		return batch(ctx, splitLines(target.Config["vhost_name"]), info, func(site string) error {
			query := url.Values{"c": {"amssl"}, "a": {"admin_amssl"}, "envs_name": {target.Config["env_name"]}, "vhost_name": {site}, "ModuleSort": {"app"}}
			res, e := q.page(ctx, http.MethodPost, "/?"+query.Encode(), url.Values{"submit_key_crt": {"y"}, "key_input1": {"key_input1"}, "key_content1": {key}, "crt_input1": {"crt_input1"}, "crt_content1": {chain}, "amh_token": {q.cfg["amh_token"]}}, map[string]string{"Cookie": q.cfg["session_cookie"]})
			if e != nil {
				return e
			}
			if strings.Contains(res.body, `id="success"`) {
				return nil
			}
			return errors.New("AMH certificate installation failed")
		})
	case "kangle", "kangleadmin":
		if p.kind == "kangleadmin" {
			if target.Config["name"] == "" {
				return info, errors.New("Kangle website user is required")
			}
			base := strings.TrimRight(p.cfg["path"], "/")
			if base == "" {
				base = "/admin"
			}
			res, e := q.page(ctx, http.MethodGet, base+"/index.php?"+url.Values{"c": {"vhost"}, "a": {"impLogin"}, "name": {target.Config["name"]}}.Encode(), nil, nil)
			if e != nil {
				return info, e
			}
			if res.code != 302 {
				return info, errors.New("Kangle website impersonation failed")
			}
		}
		if _, e = q.page(ctx, http.MethodGet, "/vhost/", nil, nil); e != nil {
			return info, e
		}
		domains := []string{"account"}
		if target.Config["type"] == "1" {
			domains = splitLines(target.Config["domains"])
		}
		return batch(ctx, domains, info, func(domain string) error {
			path := "/vhost/?c=ssl&a=ssl"
			values := url.Values{"certificate": {chain}, "certificate_key": {key}}
			if domain != "account" {
				path = "/vhost/?c=ssl&a=domainSsl"
				values.Set("domain", domain)
			}
			res, e := q.page(ctx, http.MethodPost, path, values, nil)
			if e != nil {
				return e
			}
			if res.code/100 == 2 && strings.Contains(res.body, "成功") {
				return nil
			}
			return errors.New("Kangle SSL installation failed")
		})
	case "upyun":
		if ec, ok := private.(*ecdsa.PrivateKey); ok {
			der, e := x509.MarshalECPrivateKey(ec)
			if e != nil {
				return info, e
			}
			key = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		}
		id := text(info["certificate_id"])
		if id == "" {
			v, e := q.form(ctx, "/api/https/certificate/", url.Values{"certificate": {chain}, "private_key": {key}}, nil)
			if e != nil {
				return info, e
			}
			data := obj(obj(v)["data"])
			if text(data["status"]) != "0" {
				return info, errors.New(safeError(data, p.cfg))
			}
			id = text(obj(data["result"])["certificate_id"])
			if id == "" {
				return info, errors.New("Upyun certificate ID unavailable")
			}
			info["certificate_id"] = id
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
		}
		v, e := q.request(ctx, http.MethodGet, "/api/https/certificate/search?"+url.Values{"limit": {"100"}, "domain": {leaf.Subject.CommonName}}.Encode(), nil, nil)
		if e != nil {
			return info, e
		}
		rows := obj(obj(obj(v)["data"])["result"])
		ids := []string{}
		for rid, row := range rows {
			m := obj(row)
			if rid != id && text(m["commonName"]) == leaf.Subject.CommonName && truth(m["config_domain"]) {
				ids = append(ids, rid)
			}
		}
		if len(ids) == 0 {
			return info, nil
		}
		return batch(ctx, ids, info, func(old string) error {
			v, e := q.form(ctx, "/api/https/migrate/certificate", url.Values{"new_crt_id": {id}, "old_crt_id": {old}}, nil)
			if e != nil {
				return e
			}
			if !truth(obj(obj(v)["data"])["result"]) {
				return errors.New(safeError(v, p.cfg))
			}
			return nil
		})
	}
	return info, errors.New("unknown legacy panel provider")
}

type synologyProvider struct{ *httpProvider }

func (p *synologyProvider) login(ctx context.Context) (map[string]any, error) {
	path := "/webapi/entry.cgi"
	if p.cfg["version"] == "1" {
		path = "/webapi/auth.cgi"
	}
	v, e := p.form(ctx, path, url.Values{"api": {"SYNO.API.Auth"}, "version": {"6"}, "method": {"login"}, "session": {"webui"}, "account": {p.cfg["username"]}, "passwd": {p.cfg["password"]}, "format": {"sid"}, "enable_syno_token": {"yes"}}, nil)
	if e != nil {
		return nil, e
	}
	if !truth(obj(v)["success"]) {
		return nil, errors.New("Synology login failed")
	}
	state := obj(obj(v)["data"])
	if text(state["sid"]) == "" || text(state["synotoken"]) == "" {
		return nil, errors.New("Synology session token unavailable")
	}
	return state, nil
}
func (p *synologyProvider) Validate(ctx context.Context) error { _, e := p.login(ctx); return e }
func (p *synologyProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	state, e := p.login(ctx)
	if e != nil {
		return info, e
	}
	query := url.Values{"api": {"SYNO.Core.Certificate.CRT"}, "version": {"1"}, "method": {"list"}, "_sid": {text(state["sid"])}, "SynoToken": {text(state["synotoken"])}}
	v, e := p.request(ctx, http.MethodGet, "/webapi/entry.cgi?"+query.Encode(), nil, nil)
	if e != nil {
		return info, e
	}
	if !truth(obj(v)["success"]) {
		return info, errors.New("Synology certificate list failed")
	}
	id := text(info["certificate_id"])
	for _, row := range anyList(obj(obj(v)["data"])["certificates"]) {
		m := obj(row)
		if text(obj(m["subject"])["common_name"]) == leaf.Subject.CommonName || (target.Config["desc"] != "" && text(m["desc"]) == target.Config["desc"]) {
			if id != "" && id != text(m["id"]) {
				return info, errors.New("multiple matching Synology certificates")
			}
			id = text(m["id"])
		}
	}
	query.Set("api", "SYNO.Core.Certificate")
	query.Set("method", "import")
	cert, intermediate, e := splitChain(chain)
	if e != nil {
		return info, e
	}
	files := []filePart{{"key", "key.pem", []byte(key)}, {"cert", "cert.pem", []byte(cert)}}
	if intermediate != "" {
		files = append(files, filePart{"inter_cert", "chain.pem", []byte(intermediate)})
	}
	v, e = p.multipart(ctx, http.MethodPost, "/webapi/entry.cgi?"+query.Encode(), map[string]string{"id": id, "desc": target.Config["desc"]}, files, nil)
	if e != nil {
		return info, e
	}
	if !truth(obj(v)["success"]) {
		return info, errors.New("Synology certificate import failed")
	}
	if id == "" {
		id = text(obj(obj(v)["data"])["id"])
		if id == "" {
			return info, errors.New("Synology certificate creation returned no ID")
		}
		info["certificate_id"] = id
		return info, persist(ctx, p.opts, info)
	}
	return info, nil
}

type btwafProvider struct{ *httpProvider }

func (p *btwafProvider) call(ctx context.Context, path string, body any) (map[string]any, error) {
	timestamp := strconv.FormatInt(p.opts.Now().Unix(), 10)
	v, e := p.json(ctx, http.MethodPost, path, body, map[string]string{"waf_request_time": timestamp, "waf_request_token": md5hex(timestamp + md5hex(p.cfg["key"]))})
	if e != nil {
		return nil, e
	}
	m := obj(v)
	if text(m["code"]) != "0" {
		return nil, errors.New(safeError(map[string]any{"msg": m["res"]}, p.cfg))
	}
	return obj(m["res"]), nil
}
func (p *btwafProvider) Validate(ctx context.Context) error {
	_, e := p.call(ctx, "/api/user/latest_version", nil)
	return e
}
func (p *btwafProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, e := parsePair(chain, key); e != nil {
		return info, e
	}
	if target.Config["type"] == "1" {
		_, e := p.call(ctx, "/api/config/set_cert", map[string]string{"certContent": chain, "keyContent": key})
		return info, e
	}
	return batch(ctx, splitLines(target.Config["sites"]), info, func(site string) error {
		data, e := p.call(ctx, "/api/wafmastersite/get_site_list", map[string]any{"p": 1, "p_size": 100, "site_name": site})
		if e != nil {
			return e
		}
		for _, row := range anyList(data["list"]) {
			m := obj(row)
			if text(m["site_name"]) != site {
				continue
			}
			ports := obj(m["server"])["listen_ssl_port"]
			if len(anyList(ports)) == 0 {
				ports = []string{"443"}
			}
			_, e = p.call(ctx, "/api/wafmastersite/modify_site", map[string]any{"types": "openCert", "site_id": m["site_id"], "server": map[string]any{"listen_ssl_port": ports, "ssl": map[string]any{"is_ssl": 1, "private_key": key, "full_chain": chain}}})
			return e
		}
		return errors.New("BT WAF website not found")
	})
}
