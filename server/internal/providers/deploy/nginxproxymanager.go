package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type npmProvider struct {
	*httpProvider
	token string
}

func (p *npmProvider) headers() map[string]string {
	return map[string]string{"Authorization": "Bearer " + p.token}
}
func (p *npmProvider) login(ctx context.Context) error {
	if p.cfg["email"] == "" || p.cfg["password"] == "" {
		return errors.New("NPM email and password are required")
	}
	value, err := p.json(ctx, http.MethodPost, "/api/tokens", map[string]string{"identity": p.cfg["email"], "secret": p.cfg["password"]}, nil)
	if err != nil {
		return err
	}
	p.token = text(obj(value)["token"])
	if p.token == "" {
		if truth(obj(value)["requires_2fa"]) {
			return errors.New("NPM account requires two-factor authentication")
		}
		return errors.New("NPM did not return an access token")
	}
	return nil
}
func (p *npmProvider) Validate(ctx context.Context) error {
	if err := p.login(ctx); err != nil {
		return err
	}
	_, err := p.json(ctx, http.MethodGet, "/api/nginx/certificates", nil, p.headers())
	return err
}
func (p *npmProvider) get(ctx context.Context, resource string, id string) (map[string]any, error) {
	value, err := p.json(ctx, http.MethodGet, "/api/nginx/"+resource+"/"+urlID(id), nil, p.headers())
	if err != nil {
		return nil, err
	}
	m := obj(value)
	if text(m["id"]) == "" {
		return nil, fmt.Errorf("NPM %s %s was not found", resource, id)
	}
	return m, nil
}
func (p *npmProvider) custom(ctx context.Context, id string) error {
	certificate, err := p.get(ctx, "certificates", id)
	if err != nil {
		return err
	}
	if certificate["provider"] != "other" {
		return errors.New("NPM certificate must have provider=other")
	}
	return nil
}
func (p *npmProvider) upload(ctx context.Context, id, chain, key string) error {
	leaf, intermediate, err := splitChain(chain)
	if err != nil {
		return err
	}
	files := []filePart{{"certificate", "certificate.pem", []byte(leaf)}, {"certificate_key", "certificate.key", []byte(key)}}
	if strings.TrimSpace(intermediate) != "" {
		files = append(files, filePart{"intermediate_certificate", "intermediate.pem", []byte(intermediate)})
	}
	_, err = p.multipart(ctx, http.MethodPost, "/api/nginx/certificates/"+urlID(id)+"/upload", nil, files, p.headers())
	return err
}
func (p *npmProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if _, _, _, err := parsePair(chain, key); err != nil {
		return info, err
	}
	if len(target.Domains) == 0 {
		return info, errors.New("NPM deployment domains are required")
	}
	if err := p.login(ctx); err != nil {
		return info, err
	}
	configured := target.Config["id"]
	if configured != "" && configured != "0" {
		if err := p.custom(ctx, configured); err != nil {
			return info, err
		}
		return info, p.upload(ctx, configured, chain, key)
	}
	hosts := []map[string]any{}
	if id := target.Config["host_id"]; id != "" && id != "0" {
		host, err := p.get(ctx, "proxy-hosts", id)
		if err != nil {
			return info, err
		}
		hosts = append(hosts, host)
	} else {
		value, err := p.json(ctx, http.MethodGet, "/api/nginx/proxy-hosts", nil, p.headers())
		if err != nil {
			return info, err
		}
		list, ok := value.([]any)
		if !ok {
			return info, errors.New("invalid NPM proxy-host list")
		}
		for _, item := range list {
			host := obj(item)
			hostDomains, _ := host["domain_names"].([]any)
			matched := false
			for _, candidate := range hostDomains {
				for _, domain := range target.Domains {
					if domainMatches(domain, text(candidate)) || domainMatches(text(candidate), domain) {
						matched = true
						break
					}
				}
			}
			if matched {
				details, err := p.get(ctx, "proxy-hosts", text(host["id"]))
				if err != nil {
					return info, err
				}
				hosts = append(hosts, details)
			}
		}
	}
	if len(hosts) == 0 {
		return info, errors.New("no matching NPM Proxy Host; set certificate ID or host ID")
	}
	id := text(info["certificate_id"])
	if id != "" {
		if err := p.custom(ctx, id); err != nil {
			return info, err
		}
	} else {
		for _, host := range hosts {
			existing := text(host["certificate_id"])
			if existing == "" || existing == "0" {
				continue
			}
			if err := p.custom(ctx, existing); err != nil {
				continue
			}
			if id == "" {
				id = existing
			} else if id != existing {
				return info, errors.New("matching NPM hosts use different custom certificates; set an explicit certificate ID")
			}
		}
	}
	if id == "" {
		value, err := p.json(ctx, http.MethodPost, "/api/nginx/certificates", map[string]string{"provider": "other", "nice_name": target.Domains[0]}, p.headers())
		if err != nil {
			return info, err
		}
		id = text(obj(value)["id"])
		if id == "" || id == "0" {
			return info, errors.New("NPM did not return new certificate ID")
		}
		info["certificate_id"] = id
		if err = persist(ctx, p.opts, info); err != nil {
			return info, err
		}
	}
	if err := p.upload(ctx, id, chain, key); err != nil {
		return info, err
	}
	info["certificate_id"] = id
	info["config"] = map[string]string{"id": id}
	return batch(ctx, hostIDs(hosts), info, func(hostID string) error {
		for _, host := range hosts {
			if text(host["id"]) == hostID && text(host["certificate_id"]) == id {
				return nil
			}
		}
		numeric, err := strconv.Atoi(id)
		if err != nil {
			return err
		}
		_, err = p.json(ctx, http.MethodPut, "/api/nginx/proxy-hosts/"+urlID(hostID), map[string]int{"certificate_id": numeric}, p.headers())
		return err
	})
}
func hostIDs(hosts []map[string]any) []string {
	ids := []string{}
	for _, host := range hosts {
		ids = append(ids, text(host["id"]))
	}
	return ids
}
func domainMatches(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if !strings.HasSuffix(domain, suffix) {
			return false
		}
		label := strings.TrimSuffix(domain, suffix)
		return label != "" && !strings.Contains(label, ".")
	}
	return false
}
func urlID(id string) string {
	for _, r := range id {
		if r < '0' || r > '9' {
			return "invalid-id"
		}
	}
	return id
}
