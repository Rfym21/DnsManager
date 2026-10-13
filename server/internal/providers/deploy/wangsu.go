package deploy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

type wangsuProvider struct{ *httpProvider }

func (p *wangsuProvider) call(ctx context.Context, method, resource string, body any, date string, headers map[string]string) (any, error) {
	if date == "" {
		date = p.opts.Now().UTC().Format(http.TimeFormat)
	}
	raw := []byte{}
	if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, p.base+resource, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	mac := hmac.New(sha1.New, []byte(p.cfg["apiKey"]))
	mac.Write([]byte(date))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.SetBasicAuth(p.cfg["username"], signature)
	req.Header.Set("Date", date)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
		return nil, rejectedHTTP("wangsu", resp.StatusCode, "provider request failed")
	}
	if location := resp.Header.Get("Location"); location != "" {
		return location, nil
	}
	if len(data) == 0 {
		return nil, nil
	}
	var value any
	if json.Unmarshal(data, &value) != nil {
		return nil, errors.New("invalid Wangsu JSON")
	}
	return value, nil
}
func (p *wangsuProvider) encrypt(key, date string) (string, error) {
	secret := p.cfg["spKey"]
	if secret == "" {
		secret = p.cfg["apiKey"]
	}
	material := hmacSHA256([]byte(secret), date)
	block, e := aes.NewCipher(material[16:])
	if e != nil {
		return "", e
	}
	pad := aes.BlockSize - len(key)%aes.BlockSize
	plain := append([]byte(key), bytes.Repeat([]byte{byte(pad)}, pad)...)
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, material[:16]).CryptBlocks(encrypted, plain)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}
func resourceID(value any) string {
	u, e := url.Parse(text(value))
	if e != nil {
		return ""
	}
	id := path.Base(u.Path)
	if id == "." || id == "/" {
		return ""
	}
	return id
}
func (p *wangsuProvider) Validate(ctx context.Context) error {
	if p.cfg["username"] == "" || p.cfg["apiKey"] == "" {
		return errors.New("Wangsu username and API key are required")
	}
	_, e := p.call(ctx, http.MethodGet, "/api/ssl/certificate", nil, "", nil)
	return e
}
func (p *wangsuProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	info = renewedInfo(prior, sha256hex(leaf.Raw), "cert_id", "certificate_version", "property_version", "property_id", "validation_id", "deployment_task_id")
	name := certName(leaf.Subject.CommonName, leaf.NotBefore.Unix())
	product := target.Config["product"]
	pro := product == "cdnpro" || product == "cdnpro_certificate"
	id := target.Config["cert_id"]
	if id == "" {
		id = text(info["cert_id"])
	}
	version := text(info["certificate_version"])
	if version == "" {
		version = "1"
	}
	if product == "certificate" {
		if id == "" {
			return info, errors.New("Wangsu certificate ID is required")
		}
		_, e = p.call(ctx, http.MethodPut, "/api/certificate/"+url.PathEscape(id), map[string]string{"name": name, "certificate": chain, "privateKey": key}, "", nil)
		return info, e
	}
	if !pro && product != "cdn" {
		return info, errors.New("invalid Wangsu product")
	}
	if pro {
		if product == "cdnpro_certificate" && id == "" {
			return info, errors.New("Wangsu CDN Pro certificate ID is required")
		}
		if id == "" {
			v, e := p.call(ctx, http.MethodGet, "/cdn/certificates?"+url.Values{"search": {name}}.Encode(), nil, "", nil)
			if e != nil {
				return info, e
			}
			for _, row := range anyList(obj(v)["certificates"]) {
				m := obj(row)
				if text(m["name"]) == name {
					id = text(m["certificateId"])
					break
				}
			}
		}
		if id == "" || product == "cdnpro_certificate" {
			date := p.opts.Now().UTC().Format(http.TimeFormat)
			encrypted, e := p.encrypt(key, date)
			if e != nil {
				return info, e
			}
			body := map[string]any{"name": name, "newVersion": map[string]string{"privateKey": encrypted, "certificate": chain, "comments": name}}
			method, resource := http.MethodPost, "/cdn/certificates"
			if id != "" {
				method = http.MethodPatch
				resource += "/" + url.PathEscape(id)
			} else {
				body["autoRenew"] = "Off"
			}
			v, e := p.call(ctx, method, resource, body, date, nil)
			if e != nil {
				return info, e
			}
			created := resourceID(v)
			if created == "" {
				return info, errors.New("Wangsu certificate operation returned no resource location")
			}
			if id == "" {
				id = created
				version = "1"
			} else {
				version = created
			}
			info["cert_id"] = id
			info["certificate_version"] = version
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
		}
	} else {
		if id == "" {
			v, e := p.call(ctx, http.MethodGet, "/api/ssl/certificate", nil, "", nil)
			if e != nil {
				return info, e
			}
			serial := strings.ToLower(leaf.SerialNumber.Text(16))
			for _, row := range anyList(obj(v)["ssl-certificate"]) {
				m := obj(row)
				if strings.EqualFold(text(m["certificate-serial"]), serial) {
					id = text(m["certificate-id"])
					break
				}
			}
		}
		if id == "" {
			v, e := p.call(ctx, http.MethodPost, "/api/certificate", map[string]string{"name": name, "certificate": chain, "privateKey": key}, "", nil)
			if e != nil {
				return info, e
			}
			id = resourceID(v)
			if id == "" {
				return info, errors.New("Wangsu upload returned no resource location")
			}
			info["cert_id"] = id
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
		}
		domains := splitLines(strings.ReplaceAll(target.Config["domains"], ",", "\n"))
		return batch(ctx, domains, info, func(domain string) error {
			_, e := p.call(ctx, http.MethodPut, "/api/config/certificate/batch", map[string]any{"certificateId": id, "domainNames": []string{domain}}, "", nil)
			return e
		})
	}
	actions := []any{map[string]any{"action": "deploy_cert", "certificateId": id, "version": func() int { n, _ := strconv.Atoi(version); return n }()}}
	if product == "cdnpro" {
		domain := target.Config["domain"]
		if domain == "" {
			return info, errors.New("Wangsu CDN Pro domain is required")
		}
		v, e := p.call(ctx, http.MethodGet, "/cdn/hostnames/"+url.PathEscape(domain), nil, "", nil)
		if e != nil {
			return info, e
		}
		production := obj(obj(v)["propertyInProduction"])
		property := text(production["propertyId"])
		if property == "" {
			return info, errors.New("Wangsu property is not deployed in production")
		}
		propertyVersion := text(info["property_version"])
		if propertyVersion == "" {
			v, e = p.call(ctx, http.MethodGet, "/cdn/properties/"+url.PathEscape(property)+"/versions/"+url.PathEscape(text(production["version"])), nil, "", nil)
			if e != nil {
				return info, e
			}
			configs := obj(obj(v)["configs"])
			if configs == nil {
				return info, errors.New("Wangsu property configuration unavailable")
			}
			configs["tlsCertificateId"] = id
			v, e = p.call(ctx, http.MethodPost, "/cdn/properties/"+url.PathEscape(property)+"/versions", configs, "", nil)
			if e != nil {
				return info, e
			}
			propertyVersion = resourceID(v)
			if propertyVersion == "" {
				return info, errors.New("Wangsu property version location unavailable")
			}
			info["property_version"] = propertyVersion
			info["property_id"] = property
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
		}
		validation := text(info["validation_id"])
		if validation == "" {
			n, _ := strconv.Atoi(propertyVersion)
			v, e = p.call(ctx, http.MethodPost, "/cdn/validations", map[string]any{"propertyId": property, "version": n}, "", nil)
			if e != nil {
				return info, e
			}
			validation = resourceID(v)
			if validation == "" {
				return info, errors.New("Wangsu validation location unavailable")
			}
			info["validation_id"] = validation
			if e = persist(ctx, p.opts, info); e != nil {
				return info, e
			}
		}
		for {
			v, e = p.call(ctx, http.MethodGet, "/cdn/validations/"+url.PathEscape(validation), nil, "", nil)
			if e != nil {
				return info, e
			}
			status := text(obj(v)["status"])
			if status == "failed" {
				return info, errors.New("Wangsu property validation failed")
			}
			if status == "succeeded" {
				break
			}
			if e = pollDeploy(ctx); e != nil {
				return info, e
			}
		}
		n, _ := strconv.Atoi(propertyVersion)
		actions = append(actions, map[string]any{"action": "deploy_property", "propertyId": property, "version": n})
	}
	task := text(info["deployment_task_id"])
	if task == "" {
		v, e := p.call(ctx, http.MethodPost, "/cdn/deploymentTasks", map[string]any{"target": "production", "actions": actions, "name": "Deploy certificate " + name}, "", map[string]string{"Check-Certificate": "no", "Check-Usage": "no"})
		if e != nil {
			return info, e
		}
		task = resourceID(v)
		if task == "" {
			return info, errors.New("Wangsu deployment task location unavailable")
		}
		info["deployment_task_id"] = task
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
	}
	for {
		v, e := p.call(ctx, http.MethodGet, "/cdn/deploymentTasks/"+url.PathEscape(task), nil, "", nil)
		if e != nil {
			return info, e
		}
		status := text(obj(v)["status"])
		if status == "succeeded" || status == "completed" {
			return info, nil
		}
		if status == "failed" || status == "aborted" {
			return info, errors.New("Wangsu deployment task failed")
		}
		if e = pollDeploy(ctx); e != nil {
			return info, e
		}
	}
}
