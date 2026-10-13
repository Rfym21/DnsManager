package automation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type OptimizationData struct {
	SourceURL       string            `json:"source_url"`
	SourceProvider  string            `json:"source_provider,omitempty"`
	SourceConfig    map[string]string `json:"source_config,omitempty"`
	IPTypes         []string          `json:"ip_types,omitempty"`
	LineMode        string            `json:"line_mode,omitempty"`
	IPType          string            `json:"ip_type"`
	RecordNames     []string          `json:"record_names"`
	Line            string            `json:"line"`
	TTL             int               `json:"ttl"`
	RecordCount     int               `json:"record_count"`
	IntervalSeconds int               `json:"interval_seconds"`
	LastRun         time.Time         `json:"last_run,omitempty"`
	LastIPs         []string          `json:"last_ips,omitempty"`
}

func (r *Runner) optimize(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d OptimizationData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	var requested struct {
		Action string `json:"action"`
	}
	json.Unmarshal(j.Payload, &requested)
	if requested.Action == "quota" {
		return r.optimizationQuota(ctx, d)
	}
	if len(j.Checkpoint) > 0 {
		return r.resumeOptimization(ctx, j, o)
	}
	if d.SourceProvider != "" && d.SourceProvider != "custom" {
		return r.optimizeLegacy(ctx, j, o, d)
	}
	target, err := url.Parse(d.SourceURL)
	if err != nil || target.Hostname() == "" || (target.Scheme != "https" && target.Scheme != "http") {
		return nil, errors.New("IP source requires http(s) URL")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", d.SourceURL, nil)
	if err != nil {
		return nil, err
	}
	client, err := r.Store.HTTPClient(ctx, d.SourceConfig, 20*time.Second)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New("IP source returned an error")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return nil, errors.New("IP source response exceeded limit")
	}
	ips := parseIPs(b, d.IPType)
	if d.RecordCount < 1 || d.RecordCount > 50 {
		return nil, errors.New("record count must be 1–50")
	}
	if len(ips) < d.RecordCount {
		return nil, errors.New("IP source does not contain enough valid addresses")
	}
	ips = ips[:d.RecordCount]
	var payload struct {
		Action string `json:"action"`
	}
	json.Unmarshal(j.Payload, &payload)
	if payload.Action == "test" {
		return map[string]any{"ips": ips}, nil
	}
	p, err := r.principal(ctx, j)
	if err != nil {
		return nil, err
	}
	zone, provider, err := r.provider(ctx, p, o.DomainID, "dns:write")
	if err != nil {
		return nil, err
	}
	if d.TTL < 1 {
		d.TTL = 600
	}
	if d.Line == "" {
		d.Line = "default"
	}
	d.LastRun = time.Now().UTC()
	d.LastIPs = ips
	cache := map[string][]dns.Record{}
	plan := optimizationPlan{Fields: map[string]any{"last_run": d.LastRun, "last_ips": ips}, Result: map[string]any{"ips": ips}}
	for _, name := range d.RecordNames {
		mutations, e := planOptimizationIPs(ctx, provider, name, d.Line, d.IPType, ips, d.TTL, cache)
		if e != nil {
			return nil, e
		}
		plan.Mutations = append(plan.Mutations, mutations...)
	}
	r.Store.Audit(ctx, j.OwnerID, "optimization.plan", "domain", zone.ID, zone.ID, "", map[string]any{"job_id": j.ID, "operations": len(plan.Mutations)})
	return r.executeOptimizationPlan(ctx, j, o, provider, plan)
}
func parseIPs(b []byte, family string) []string {
	var values any
	if json.Unmarshal(b, &values) != nil {
		values = string(b)
	}
	found := []string{}
	seen := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			for _, token := range strings.FieldsFunc(x, func(r rune) bool {
				return r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ',' || r == '|' || r == '"'
			}) {
				ip := net.ParseIP(strings.TrimSpace(token))
				if ip == nil {
					continue
				}
				if family == "ipv4" && ip.To4() == nil || family == "ipv6" && ip.To4() != nil {
					continue
				}
				s := ip.String()
				if !seen[s] {
					seen[s] = true
					found = append(found, s)
				}
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			for _, key := range []string{"ip", "ipv4", "ipv6", "address", "data", "result", "ips", "list", "rows"} {
				if item, ok := x[key]; ok {
					walk(item)
				}
			}
		}
	}
	walk(values)
	return found
}
