package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const qzyunRouterState = "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(product)%22%2C%7B%22children%22%3A%5B%22certificate%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"

type qzyunProvider struct{ *httpProvider }

func (p *qzyunProvider) action(ctx context.Context, q *httpProvider, page, name string) (string, error) {
	scripts := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`).FindAllStringSubmatch(page, -1)
	origin, _ := url.Parse(p.base)
	pattern := regexp.MustCompile(`(?s)createServerReference\)\("([a-f0-9]{32,64})"[^)]{0,300},"` + regexp.QuoteMeta(name) + `"\)`)
	for _, script := range scripts {
		u, e := url.Parse(html.UnescapeString(script[1]))
		if e != nil {
			continue
		}
		u = origin.ResolveReference(u)
		if u.Scheme != origin.Scheme || u.Host != origin.Host {
			continue
		}
		res, e := q.page(ctx, http.MethodGet, u.RequestURI(), nil, nil)
		if e != nil {
			return "", e
		}
		if m := pattern.FindStringSubmatch(res.body); len(m) > 1 {
			return m[1], nil
		}
	}
	return "", errors.New("Qzyun server action was not found; its console protocol may have changed")
}
func (p *qzyunProvider) post(ctx context.Context, q *httpProvider, path, action string, fields map[string]string) (pageResponse, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for k, v := range fields {
		if e := writer.WriteField(k, v); e != nil {
			return pageResponse{}, e
		}
	}
	if e := writer.Close(); e != nil {
		return pageResponse{}, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, &body)
	if e != nil {
		return pageResponse{}, e
	}
	req.Header.Set("Accept", "text/x-component")
	req.Header.Set("next-action", action)
	req.Header.Set("next-router-state-tree", qzyunRouterState)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Origin", p.base)
	req.Header.Set("Referer", p.base+path)
	resp, e := q.client.Do(req)
	if e != nil {
		return pageResponse{}, e
	}
	defer resp.Body.Close()
	raw, e := readLimited(resp.Body)
	if e == nil && resp.StatusCode >= 400 {
		e = rejectedHTTP("qzyun", resp.StatusCode, "provider request failed")
	}
	return pageResponse{resp.StatusCode, string(raw), resp.Header.Get("Location")}, e
}
func actionResult(body string) map[string]any {
	lines := strings.Split(body, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		at := strings.Index(line, ":{")
		if at < 0 {
			continue
		}
		var v map[string]any
		if json.Unmarshal([]byte(line[at+1:]), &v) == nil {
			if _, ok := v["success"]; ok {
				return v
			}
			if _, ok := v["error"]; ok {
				return v
			}
		}
	}
	return nil
}
func (p *qzyunProvider) login(ctx context.Context) (*httpProvider, error) {
	if p.cfg["email"] == "" || p.cfg["password"] == "" {
		return nil, errors.New("Qzyun email and password are required")
	}
	q := newSession(p.httpProvider)
	page, e := q.page(ctx, http.MethodGet, "/login", nil, nil)
	if e != nil {
		return nil, e
	}
	action, e := p.action(ctx, q, page.body, "login")
	if e != nil {
		return nil, e
	}
	res, e := p.post(ctx, q, "/login", action, map[string]string{"1_email": p.cfg["email"], "1_password": p.cfg["password"], "0": `[{"error":null,"success":false},"$K1"]`})
	if e != nil {
		return nil, e
	}
	if !q.sessionCookie() {
		return nil, errors.New("Qzyun login did not establish a session")
	}
	if res.code/100 == 3 {
		return q, nil
	}
	result := actionResult(res.body)
	if res.code != 200 || result == nil || !truth(result["success"]) {
		return nil, errors.New("Qzyun login failed")
	}
	return q, nil
}
func (p *qzyunProvider) Validate(ctx context.Context) error { _, e := p.login(ctx); return e }
func rscText(source string) string {
	matches := regexp.MustCompile(`(?s)self\.__next_f\.push\((\[.*?\])\)</script>`).FindAllStringSubmatch(source, -1)
	var out strings.Builder
	for _, m := range matches {
		var v []any
		if json.Unmarshal([]byte(m[1]), &v) == nil && len(v) > 1 && text(v[0]) == "1" {
			out.WriteString(text(v[1]))
		}
	}
	return out.String()
}
func rscObjects(source string) []map[string]any {
	objects := []map[string]any{}
	var collect func(any)
	collect = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			objects = append(objects, v)
			for _, child := range v {
				collect(child)
			}
		case []any:
			for _, child := range v {
				collect(child)
			}
		}
	}
	for start := 0; start < len(source); {
		offset := strings.IndexByte(source[start:], '{')
		if offset < 0 {
			break
		}
		start += offset
		decoder := json.NewDecoder(strings.NewReader(source[start:]))
		decoder.UseNumber()
		var value map[string]any
		if decoder.Decode(&value) == nil {
			collect(value)
			start += int(decoder.InputOffset())
		} else {
			start++
		}
	}
	return objects
}
func findQzyunCertificate(page, name string) (string, error) {
	ids := map[string]bool{}
	for _, m := range rscObjects(rscText(page)) {
		if text(m["name"]) == name && m["startTime"] != nil && m["privateKey"] != nil && m["content"] != nil && text(m["documentId"]) != "" {
			ids[text(m["documentId"])] = true
		}
	}
	if len(ids) > 1 {
		return "", errors.New("multiple Qzyun certificates share this name")
	}
	for id := range ids {
		return id, nil
	}
	return "", nil
}
func (p *qzyunProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, e := parsePair(chain, key); e != nil {
		return info, e
	}
	certificate := target.Config["certificate"]
	if certificate == "" {
		return info, errors.New("Qzyun certificate name or document ID is required")
	}
	q, e := p.login(ctx)
	if e != nil {
		return info, e
	}
	page, e := q.page(ctx, http.MethodGet, "/certificate", nil, nil)
	if e != nil {
		return info, e
	}
	id := text(info["document_id"])
	if id == "" && regexp.MustCompile(`^[a-zA-Z0-9]{24}$`).MatchString(certificate) {
		id = certificate
	}
	if id == "" {
		id, e = findQzyunCertificate(page.body, certificate)
		if e != nil {
			return info, e
		}
	}
	created := false
	if id == "" {
		action, e := p.action(ctx, q, page.body, "addCertificateAction")
		if e != nil {
			return info, e
		}
		res, e := p.post(ctx, q, "/certificate", action, map[string]string{"1_certificateName": certificate, "1_serverCertificate": chain, "1_privateKey": key, "0": `[{"success":false,"message":""},"$K1"]`})
		if e != nil {
			return info, e
		}
		if res.code != 200 || !truth(actionResult(res.body)["success"]) {
			return info, errors.New("Qzyun certificate creation failed")
		}
		page, e = q.page(ctx, http.MethodGet, "/certificate", nil, nil)
		if e != nil {
			return info, e
		}
		id, e = findQzyunCertificate(page.body, certificate)
		if e != nil {
			return info, e
		}
		if id == "" {
			return info, errors.New("Qzyun created certificate document ID unavailable")
		}
		info["document_id"] = id
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
		created = true
	}
	if !created {
		action, e := p.action(ctx, q, page.body, "updateCertificateAction")
		if e != nil {
			return info, e
		}
		res, e := p.post(ctx, q, "/certificate", action, map[string]string{"1_certDocumentId": id, "1_serverCertificate": chain, "1_privateKey": key, "0": `[{"success":false,"message":""},"$K1"]`})
		if e != nil {
			return info, e
		}
		if res.code != 200 || !truth(actionResult(res.body)["success"]) {
			return info, errors.New("Qzyun certificate update failed")
		}
	}
	info["document_id"] = id
	domain := target.Config["domain"]
	if domain == "" {
		return info, nil
	}
	domainPage, e := q.page(ctx, http.MethodGet, "/cdn/domain/"+url.PathEscape(domain), nil, nil)
	if e != nil {
		return info, e
	}
	var domainInfo map[string]any
	for _, m := range rscObjects(rscText(domainPage.body)) {
		if text(m["domain"]) == domain && m["id"] != nil && text(m["documentId"]) != "" {
			domainInfo = m
			break
		}
	}
	if domainInfo == nil {
		return info, errors.New("Qzyun CDN domain not found")
	}
	page, e = q.page(ctx, http.MethodGet, "/certificate", nil, nil)
	if e != nil {
		return info, e
	}
	name := certificate
	for _, m := range rscObjects(rscText(page.body)) {
		if text(m["documentId"]) == id && m["content"] != nil {
			name = text(m["name"])
			for _, d := range anyList(m["cdnDomains"]) {
				if text(obj(d)["domain"]) == domain {
					return info, nil
				}
			}
			break
		}
	}
	action, e := p.action(ctx, q, page.body, "bindDomainCdnServer")
	if e != nil {
		return info, e
	}
	res, e := p.post(ctx, q, "/certificate", action, map[string]string{"1_domainName": domain, "1_Id": text(domainInfo["id"]), "1_documentId": text(domainInfo["documentId"]), "1_CertificateName": name, "1_ServerCertificate": chain, "1_CertificateDocumentId": id, "1_PrivateKey": key, "0": `[{"success":false,"message":""},"$K1"]`})
	if e != nil {
		return info, e
	}
	if res.code != 200 || !truth(actionResult(res.body)["success"]) {
		return info, errors.New("Qzyun CDN certificate binding failed")
	}
	return info, nil
}
