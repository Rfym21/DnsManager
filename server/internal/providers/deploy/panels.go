package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type panelProvider struct{ *httpProvider }

func (p *panelProvider) call(ctx context.Context, method, path string, params map[string]string) (any, error) {
	switch p.kind {
	case "btpanel":
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		timestamp := strconv.FormatInt(p.opts.Now().Unix(), 10)
		values.Set("request_time", timestamp)
		values.Set("request_token", md5hex(timestamp+md5hex(p.cfg["key"])))
		return p.form(ctx, path, values, nil)
	case "mwpanel":
		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}
		headers := map[string]string{"app-id": p.cfg["appid"], "app-secret": p.cfg["appsecret"]}
		if method == http.MethodGet || len(params) == 0 {
			return p.request(ctx, http.MethodGet, path, nil, headers)
		}
		return p.form(ctx, path, values, headers)
	case "ratpanel", "acepanel":
		var body []byte
		if params != nil {
			var err error
			body, err = json.Marshal(params)
			if err != nil {
				return nil, err
			}
		}
		u, _ := url.Parse(p.base + "/api" + path)
		canonicalPath := u.Path
		if i := strings.Index(canonicalPath, "/api"); i >= 0 {
			canonicalPath = canonicalPath[i:]
		}
		canonical := method + "\n" + canonicalPath + "\n" + u.RawQuery + "\n" + sha256hex(body)
		timestamp := strconv.FormatInt(p.opts.Now().Unix(), 10)
		signed := "HMAC-SHA256\n" + timestamp + "\n" + sha256hex([]byte(canonical))
		mac := hmac.New(sha256.New, []byte(p.cfg["token"]))
		mac.Write([]byte(signed))
		headers := map[string]string{"Content-Type": "application/json", "X-Timestamp": timestamp, "Authorization": "HMAC-SHA256 Credential=" + p.cfg["id"] + ", Signature=" + hex.EncodeToString(mac.Sum(nil))}
		return p.request(ctx, method, "/api"+path, body, headers)
	}
	return nil, errors.New("unknown panel protocol")
}
func (p *panelProvider) checkResult(value any) error {
	m := obj(value)
	switch p.kind {
	case "ratpanel", "acepanel":
		if m["msg"] == "success" {
			return nil
		}
	default:
		if truth(m["status"]) || m["sites_path"] != nil {
			return nil
		}
	}
	return errors.New(safeError(value, p.cfg))
}
func (p *panelProvider) Validate(ctx context.Context) error {
	var path string
	method := http.MethodPost
	switch p.kind {
	case "btpanel":
		if p.cfg["key"] == "" {
			return errors.New("panel API key is required")
		}
		path = "/config?action=get_config"
	case "mwpanel":
		if p.cfg["appid"] == "" || p.cfg["appsecret"] == "" {
			return errors.New("panel app-id and app-secret are required")
		}
		path = "/task/count"
		method = http.MethodGet
	case "ratpanel", "acepanel":
		if p.cfg["id"] == "" || p.cfg["token"] == "" {
			return errors.New("panel token ID and secret are required")
		}
		path = "/user/info"
		method = http.MethodGet
	}
	value, err := p.call(ctx, method, path, nil)
	if err != nil {
		return err
	}
	return p.checkResult(value)
}
func (p *panelProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, err := parsePair(chain, key); err != nil {
		return info, err
	}
	kind := target.Config["type"]
	if kind == "1" {
		path := ""
		params := map[string]string{}
		switch p.kind {
		case "btpanel":
			path = "/config?action=SavePanelSSL"
			params = map[string]string{"privateKey": key, "certPem": chain}
		case "mwpanel":
			path = "/setting/save_panel_ssl"
			params = map[string]string{"privateKey": key, "certPem": chain, "choose": "local"}
		case "ratpanel", "acepanel":
			path = "/setting/cert"
			params = map[string]string{"cert": chain, "key": key}
		}
		value, err := p.call(ctx, http.MethodPost, path, params)
		if err != nil {
			return info, err
		}
		return info, p.checkResult(value)
	}
	return batch(ctx, splitLines(target.Config["sites"]), info, func(site string) error {
		path := ""
		params := map[string]string{}
		switch p.kind {
		case "btpanel":
			params = map[string]string{"key": key, "csr": chain}
			switch kind {
			case "2":
				path = "/plugin?action=a&name=mail_sys&s=set_mail_certificate_multiple"
				params["domain"] = site
				params["act"] = "add"
			case "3":
				path = "/mod/docker/com/set_ssl"
				params["site_name"] = site
			case "4":
				path = "/mod/proxy/com/set_ssl"
				params["site_name"] = site
			case "", "0":
				path = "/site?action=SetSSL"
				params["type"] = "0"
				params["siteName"] = site
			default:
				return errors.New("invalid BT deployment type")
			}
		case "mwpanel":
			path = "/site/set_ssl"
			params = map[string]string{"type": "1", "siteName": site, "key": key, "csr": chain}
		case "ratpanel", "acepanel":
			path = "/website/cert"
			params = map[string]string{"name": site, "cert": chain, "key": key}
		}
		value, err := p.call(ctx, http.MethodPost, path, params)
		if err != nil {
			return err
		}
		return p.checkResult(value)
	})
}
