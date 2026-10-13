package deploy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type btwinProvider struct{ *httpProvider }

func (p *btwinProvider) auth() url.Values {
	timestamp := strconv.FormatInt(p.opts.Now().Unix(), 10)
	return url.Values{"request_time": {timestamp}, "request_token": {md5hex(timestamp + md5hex(p.cfg["key"]))}}
}
func (p *btwinProvider) call(ctx context.Context, path string, body map[string]string) (map[string]any, error) {
	values := p.auth()
	for k, v := range body {
		values.Set(k, v)
	}
	v, e := p.form(ctx, path, values, nil)
	return obj(v), e
}
func (p *btwinProvider) Validate(ctx context.Context) error {
	if p.cfg["key"] == "" {
		return errors.New("BT Windows API key is required")
	}
	v, e := p.call(ctx, "/config/get_config", nil)
	if e != nil {
		return e
	}
	if !truth(obj(v["panel"])["status"]) {
		return errors.New(safeError(v, p.cfg))
	}
	return nil
}
func (p *btwinProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, e := parsePair(chain, key); e != nil {
		return info, e
	}
	if target.Config["type"] == "1" {
		v, e := p.call(ctx, "/config/set_panel_ssl", map[string]string{"ssl_key": key, "ssl_pem": chain})
		if e != nil {
			return info, e
		}
		if !truth(v["status"]) {
			return info, errors.New(safeError(v, p.cfg))
		}
		return info, nil
	}
	if target.Config["type"] != "" && target.Config["type"] != "0" {
		return info, errors.New("invalid BT Windows deployment type")
	}
	pfxPath, password := "", ""
	if target.Config["is_iis"] == "1" {
		v, e := p.call(ctx, "/panel/get_config", nil)
		if e != nil {
			return info, e
		}
		if text(obj(v["config"])["webserver"]) != "iis" {
			return info, errors.New("BT Windows server is not IIS")
		}
		soft := text(obj(v["paths"])["soft"])
		if soft == "" {
			return info, errors.New("BT Windows soft path unavailable")
		}
		dir := strings.TrimRight(soft, "/\\") + "/temp/ssl/" + randomSuffix()
		password = randomSuffix()
		pfx, e := encodePFX(chain, key, password)
		if e != nil {
			return info, e
		}
		values := map[string]string{"path": dir, "filename": "cert.pfx", "size": strconv.Itoa(len(pfx)), "start": "0", "force": "true"}
		for k, v := range p.auth() {
			values[k] = v[0]
		}
		upload, e := p.multipart(ctx, http.MethodPost, "/files/upload", values, []filePart{{"blob", "cert.pfx", pfx}}, nil)
		if e != nil {
			return info, e
		}
		if !truth(obj(upload)["status"]) {
			return info, errors.New(safeError(upload, p.cfg))
		}
		pfxPath = dir + "/cert.pfx"
	}
	return batch(ctx, splitLines(target.Config["sites"]), info, func(site string) error {
		if pfxPath != "" {
			v, e := p.call(ctx, "/site/set_site_domain_ssl", map[string]string{"domain": site, "path": pfxPath, "password": password})
			if e != nil {
				return e
			}
			if !truth(v["status"]) {
				return errors.New(safeError(v, p.cfg))
			}
			return nil
		}
		v, e := p.call(ctx, "/datalist/get_data_list", map[string]string{"table": "sites", "search_type": "PHP", "search": site, "p": "1", "limit": "100", "type": "-1"})
		if e != nil {
			return e
		}
		id := ""
		for _, row := range anyList(v["data"]) {
			m := obj(row)
			if text(m["name"]) == site {
				id = text(m["id"])
				break
			}
		}
		if id == "" {
			return errors.New("BT Windows website not found")
		}
		v, e = p.call(ctx, "/site/set_site_ssl", map[string]string{"siteid": id, "status": "true", "sslType": "", "cert": chain, "key": key})
		if e != nil {
			return e
		}
		if !truth(v["status"]) {
			return errors.New(safeError(v, p.cfg))
		}
		return nil
	})
}
