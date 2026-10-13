package automation

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type optimizationPlan struct {
	Mutations []mutationIntent `json:"mutations"`
	Fields    map[string]any   `json:"fields"`
	Result    map[string]any   `json:"result"`
}

func (r *Runner) resumeOptimization(ctx context.Context, j store.Job, o store.Object) (any, error) {
	var plan optimizationPlan
	if json.Unmarshal(j.Checkpoint, &plan) != nil || plan.Fields == nil {
		return nil, errors.New("优选执行计划无效")
	}
	p, err := r.principal(ctx, j)
	if err != nil {
		return nil, err
	}
	_, provider, err := r.provider(ctx, p, o.DomainID, "dns:write")
	if err != nil {
		return nil, err
	}
	return r.executeOptimizationPlan(ctx, j, o, provider, plan)
}
func (r *Runner) executeOptimizationPlan(ctx context.Context, j store.Job, o store.Object, p dns.Provider, plan optimizationPlan) (any, error) {
	if len(j.Checkpoint) == 0 {
		if err := r.Store.CheckpointJob(ctx, j, plan); err != nil {
			return nil, err
		}
	}
	for index, intent := range plan.Mutations {
		if _, err := r.mutateDNS(ctx, j, p, index, intent.Operation, intent.Record); err != nil {
			return nil, err
		}
	}
	if _, err := r.Store.SaveObjectRuntime(ctx, o, j, plan.Fields, "", nil); err != nil {
		return nil, err
	}
	return plan.Result, nil
}

// Planning completes all reads before any write. A CNAME is updated into the
// first replacement; excess old records are removed after replacements exist.
func planOptimizationIPs(ctx context.Context, p dns.Provider, name, line, family string, ips []string, ttl int, cache map[string][]dns.Record) ([]mutationIntent, error) {
	if len(ips) == 0 {
		return nil, errors.New("优选IP不能为空")
	}
	rows, loaded := cache[name]
	if !loaded {
		for page := 1; page <= 100; page++ {
			result, err := p.ListRecords(ctx, dns.ListOptions{Name: name, Page: page, PageSize: 100})
			if err != nil {
				return nil, err
			}
			for _, r := range result.Rows {
				if r.Name == name {
					rows = append(rows, r)
				}
			}
			if len(result.Rows) < 100 || (result.Total > 0 && page*100 >= result.Total) {
				break
			}
			if page == 100 {
				return nil, errors.New("优选记录超过读取限制")
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	}
	typ := "A"
	if family == "ipv6" {
		typ = "AAAA"
	}
	existing, aliases, unaffected := []dns.Record{}, []dns.Record{}, []dns.Record{}
	for _, record := range rows {
		if record.Line == line && record.Type == typ {
			existing = append(existing, record)
		} else if record.Line == line && record.Type == "CNAME" {
			aliases = append(aliases, record)
		} else {
			unaffected = append(unaffected, record)
		}
	}
	plan := []mutationIntent{}
	desiredRows := []dns.Record{}
	if p.Descriptor().ID == "huawei" {
		values := slices.Clone(ips)
		slices.Sort(values)
		desired := dns.Record{Name: name, Type: typ, Value: values[0], Values: values, Line: line, TTL: ttl, Enabled: true}
		operation := "create"
		if len(existing) > 0 {
			desired.ID = existing[0].ID
			existing = existing[1:]
			operation = "update"
		} else if len(aliases) > 0 {
			desired.ID = aliases[0].ID
			aliases = aliases[1:]
			operation = "update"
		}
		plan = append(plan, mutationIntent{Operation: operation, Record: desired})
		desiredRows = append(desiredRows, desired)
	} else {
		used := map[string]bool{}
		surplus := []dns.Record{}
		for _, record := range existing {
			if slices.Contains(ips, record.Value) && !used[record.Value] {
				used[record.Value] = true
				desired := record
				desired.TTL = ttl
				desired.Enabled = true
				if !dns.DesiredEqual(record, desired) {
					plan = append(plan, mutationIntent{Operation: "update", Record: desired})
				}
				desiredRows = append(desiredRows, desired)
			} else {
				surplus = append(surplus, record)
			}
		}
		surplus = append(surplus, aliases...)
		aliases = nil
		for _, ip := range ips {
			if used[ip] {
				continue
			}
			desired := dns.Record{Name: name, Type: typ, Value: ip, Line: line, TTL: ttl, Enabled: true}
			operation := "create"
			if len(surplus) > 0 {
				desired.ID = surplus[0].ID
				surplus = surplus[1:]
				operation = "update"
			}
			plan = append(plan, mutationIntent{Operation: operation, Record: desired})
			desiredRows = append(desiredRows, desired)
		}
		existing = surplus
	}
	for _, old := range append(existing, aliases...) {
		plan = append(plan, mutationIntent{Operation: "delete", Record: old})
	}
	cache[name] = append(unaffected, desiredRows...)
	return plan, nil
}
