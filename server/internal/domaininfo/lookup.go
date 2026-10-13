// Package domaininfo resolves registry dates without inventing an expiration
// date when a registry does not publish it. RDAP uses IANA's bootstrap; WHOIS is
// a bounded fallback for registries that still expose dates only on port 43.
package domaininfo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type Dates struct {
	Domain       string     `json:"domain"`
	RegisteredAt *time.Time `json:"registered_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Source       string     `json:"source"`
}

type Lookup struct {
	Client       *http.Client
	BootstrapURL string
	Whois        func(context.Context, string, string) (string, error)
	mu           sync.Mutex
	services     map[string]string
	loaded       time.Time
}

func (l *Lookup) Resolve(ctx context.Context, name string) (Dates, error) {
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if err != nil {
		return Dates{}, errors.New("invalid domain")
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(ascii))
	if err != nil {
		return Dates{}, errors.New("domain has no registrable suffix")
	}
	if dates, err := l.rdap(ctx, zone); err == nil {
		return dates, nil
	}
	query := l.Whois
	if query == nil {
		query = queryWhois
	}
	tld := zone[strings.LastIndex(zone, ".")+1:]
	root, err := query(ctx, "whois.iana.org", tld)
	if err != nil {
		return Dates{}, errors.New("registry dates are unavailable")
	}
	server := referral(root, "whois:")
	if server == "" {
		return Dates{}, errors.New("registry does not publish a WHOIS service")
	}
	body, err := query(ctx, server, zone)
	if err != nil {
		return Dates{}, errors.New("registry dates are unavailable")
	}
	dates := parseWhois(zone, body)
	if dates.ExpiresAt == nil {
		if next := referral(body, "registrar whois server:"); next != "" && next != server {
			if other, err := query(ctx, next, zone); err == nil {
				dates = parseWhois(zone, other)
			}
		}
	}
	if dates.ExpiresAt == nil {
		return dates, errors.New("registry does not publish an expiration date")
	}
	return dates, nil
}

func (l *Lookup) client() *http.Client {
	if l.Client != nil {
		return l.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}
func (l *Lookup) endpoint(ctx context.Context, zone string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.services == nil || time.Since(l.loaded) > 24*time.Hour {
		address := l.BootstrapURL
		if address == "" {
			address = "https://data.iana.org/rdap/dns.json"
		}
		req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
		if err != nil {
			return "", err
		}
		res, err := l.client().Do(req)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return "", errors.New("RDAP bootstrap failed")
		}
		var bootstrap struct {
			Services [][][]string `json:"services"`
		}
		if err = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&bootstrap); err != nil {
			return "", err
		}
		services := map[string]string{}
		for _, service := range bootstrap.Services {
			if len(service) != 2 || len(service[1]) == 0 {
				continue
			}
			base := service[1][0]
			for _, candidate := range service[1] {
				if strings.HasPrefix(candidate, "https://") {
					base = candidate
					break
				}
			}
			u, err := url.Parse(base)
			if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
				continue
			}
			for _, suffix := range service[0] {
				services[strings.ToLower(suffix)] = strings.TrimRight(base, "/")
			}
		}
		l.services, l.loaded = services, time.Now()
	}
	base := l.services[zone[strings.LastIndex(zone, ".")+1:]]
	if base == "" {
		return "", errors.New("no RDAP service for suffix")
	}
	return base + "/domain/" + url.PathEscape(zone), nil
}
func (l *Lookup) rdap(ctx context.Context, zone string) (Dates, error) {
	d := Dates{Domain: zone, Source: "rdap"}
	endpoint, err := l.endpoint(ctx, zone)
	if err != nil {
		return d, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return d, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	res, err := l.client().Do(req)
	if err != nil {
		return d, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return d, errors.New("RDAP lookup failed")
	}
	var body struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&body); err != nil {
		return d, err
	}
	for _, event := range body.Events {
		t, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			continue
		}
		t = t.UTC()
		switch event.Action {
		case "registration":
			d.RegisteredAt = &t
		case "expiration":
			d.ExpiresAt = &t
		}
	}
	if d.ExpiresAt == nil {
		return d, errors.New("registry does not publish an expiration date")
	}
	return d, nil
}
func referral(body, field string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), field) {
			host := strings.TrimSpace(line[len(field):])
			if regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(host) && strings.Contains(host, ".") {
				return host
			}
		}
	}
	return ""
}
func queryWhois(ctx context.Context, host, query string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, "43"))
	if err != nil {
		return "", err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	if _, err = c.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(c, 1<<20))
	return string(b), err
}
func parseWhois(zone, body string) Dates {
	d := Dates{Domain: zone, Source: "whois"}
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		var dest **time.Time
		switch key {
		case "creation date", "created", "created on", "registration time", "registered on":
			dest = &d.RegisteredAt
		case "registry expiry date", "registrar registration expiration date", "expiry date", "expiration date", "paid-till", "renewal date", "expiration time", "expires":
			dest = &d.ExpiresAt
		default:
			continue
		}
		value = strings.TrimSpace(value)
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02 15:04:05", "2006-01-02", "02-Jan-2006", "2006.01.02"} {
			if t, err := time.Parse(layout, value); err == nil {
				t = t.UTC()
				*dest = &t
				break
			}
		}
	}
	return d
}
