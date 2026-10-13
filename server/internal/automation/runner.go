package automation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type Runner struct {
	Store *store.Store
	// Optional ports keep crash/recovery tests independent of public DNS and
	// supplier credentials. Production uses the native provider and resolver.
	DNSFactory  func(string, map[string]string, string, string) (dns.Provider, error)
	LookupCNAME func(context.Context, string) (string, error)
}

func (r *Runner) Handlers() map[string]Handler {
	return map[string]Handler{
		"record_batch": r.recordBatch, "schedules": r.schedule, "monitors": r.monitor, "optimizations": r.optimize,
	}
}
func (r *Runner) principal(ctx context.Context, j store.Job) (store.Principal, error) {
	u, err := r.Store.User(ctx, j.OwnerID)
	if err != nil {
		return store.Principal{}, err
	}
	if !u.Enabled {
		return store.Principal{}, store.ErrForbidden
	}
	p := store.Principal{User: u}
	if j.Submission != nil {
		p.DomainID, p.Scopes, p.Token, p.TokenHash = j.Submission.DomainID, j.Submission.Scopes, j.Submission.Token, j.Submission.TokenHash
		if p.Token {
			var active int
			if err = r.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_tokens WHERE token_hash=? AND user_id=? AND expires_at>UTC_TIMESTAMP(6)", p.TokenHash, u.ID).Scan(&active); err != nil {
				return p, err
			}
			if active != 1 {
				return p, store.ErrForbidden
			}
		}
		if p.DomainID != "" {
			var enabled bool
			if err = r.Store.DB.QueryRowContext(ctx, "SELECT quicklogin_enabled FROM domains WHERE id=?", p.DomainID).Scan(&enabled); err != nil || !enabled {
				return p, store.ErrForbidden
			}
			allowed, e := r.Store.CanDomain(ctx, store.Principal{User: u}, p.DomainID, "dns:write")
			if e != nil || !allowed {
				return p, store.ErrForbidden
			}
		}
	} else if j.Kind == "record_batch" {
		return p, errors.New("legacy queued batch requires resubmission to retain authorization")
	}
	return p, nil
}
func (r *Runner) provider(ctx context.Context, p store.Principal, domainID, action string) (store.Domain, dns.Provider, error) {
	allowed, err := r.Store.CanDomain(ctx, p, domainID, action)
	if err != nil {
		return store.Domain{}, nil, err
	}
	if !allowed {
		return store.Domain{}, nil, store.ErrForbidden
	}
	d, err := r.Store.Domain(ctx, domainID)
	if err != nil {
		return d, nil, err
	}
	account, err := r.Store.Account(ctx, d.AccountID)
	if err != nil {
		return d, nil, err
	}
	if r.DNSFactory != nil {
		p, err := r.DNSFactory(account.Provider, account.Config, d.ProviderDomainID, d.ASCIIName)
		return d, p, err
	}
	client, err := r.Store.HTTPClient(ctx, account.Config, 25*time.Second)
	if err != nil {
		return d, nil, err
	}
	provider, err := dns.NewWithOptions(account.Provider, account.Config, d.ProviderDomainID, d.ASCIIName, dns.FactoryOptions{Client: client})
	return d, provider, err
}
func (r *Runner) check(ctx context.Context, j store.Job) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	current, err := r.Store.Job(ctx, j.ID)
	if err != nil {
		return err
	}
	if current.CancelRequested {
		return store.ErrCancelled
	}
	if current.FencingToken != j.FencingToken || current.LeaseOwner != j.LeaseOwner {
		return store.ErrLeaseLost
	}
	p, err := r.principal(ctx, j)
	if err != nil {
		return err
	}
	if j.Kind != "record_batch" && (!p.Admin() || !p.AllowsScope("admin")) {
		return store.ErrForbidden
	}
	ids := []string{}
	if j.DomainID != "" {
		ids = append(ids, j.DomainID)
	}
	if j.Kind == "record_batch" {
		var data struct {
			IDs []string `json:"domain_ids"`
		}
		if json.Unmarshal(j.Payload, &data) != nil {
			return store.ErrForbidden
		}
		ids = append(ids, data.IDs...)
	}
	for _, id := range ids {
		allowed, err := r.Store.CanDomain(ctx, p, id, "dns:write")
		if err != nil {
			return err
		}
		if !allowed {
			return store.ErrForbidden
		}
	}
	if j.ResourceID != "" {
		var saved struct {
			Scheduled     bool  `json:"scheduled"`
			ConfigVersion int64 `json:"config_version"`
		}
		json.Unmarshal(j.Payload, &saved)
		if saved.ConfigVersion > 0 || saved.Scheduled {
			o, e := r.Store.Object(ctx, j.ResourceID)
			if e != nil {
				return e
			}
			if (saved.Scheduled && !o.Active) || (saved.ConfigVersion > 0 && saved.ConfigVersion != o.ConfigVersion) {
				return errors.New("任务提交后配置已修改或计划已暂停，请重新提交")
			}
		}
	}
	return nil
}
func (r *Runner) recordBatch(ctx context.Context, j store.Job) (any, error) {
	var payload struct {
		DomainIDs []string     `json:"domain_ids"`
		Records   []dns.Record `json:"records"`
		Operation string       `json:"operation"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return nil, err
	}
	p, err := r.principal(ctx, j)
	if err != nil {
		return nil, err
	}
	existing, err := r.Store.JobItems(ctx, j.ID)
	if err != nil {
		return nil, err
	}
	done := map[int]store.JobItem{}
	for _, item := range existing {
		done[item.Index] = item
	}
	failed, unknown, success := 0, 0, 0
	for dIndex, id := range payload.DomainIDs {
		_, provider, err := r.provider(ctx, p, id, "dns:write")
		if err != nil {
			return nil, err
		}
		for recordIndex, record := range payload.Records {
			index := dIndex*len(payload.Records) + recordIndex
			if prior, ok := done[index]; ok {
				switch prior.State {
				case "succeeded":
					success++
					continue
				case "failed":
					failed++
					continue
				case "unknown", "running":
					unknown++
					continue
				}
			}
			if err = r.check(ctx, j); err != nil {
				return map[string]int{"succeeded": success, "failed": failed, "unknown": unknown}, err
			}
			// The durable intent precedes the external mutation. A crashed/ambiguous item
			// is exposed as unknown rather than blindly creating it again.
			detail, _ := json.Marshal(map[string]any{"domain_id": id, "operation": payload.Operation, "record": record})
			if err = r.Store.SaveJobItem(ctx, j, store.JobItem{Index: index, ResourceID: record.ID, State: "running", Detail: detail}); err != nil {
				return nil, err
			}
			var result dns.Record
			switch payload.Operation {
			case "create":
				err = dns.ValidateRecord(record, "example.invalid")
				if err == nil {
					result, err = provider.CreateRecord(ctx, record)
				}
			case "update":
				result, err = provider.UpdateRecord(ctx, record.ID, record)
			case "delete":
				err = provider.DeleteRecord(ctx, record.ID)
			case "enable", "disable":
				err = provider.SetStatus(ctx, record.ID, payload.Operation == "enable")
			case "remark":
				err = provider.SetRemark(ctx, record.ID, record.Remark)
			default:
				err = errors.New("invalid record batch operation")
			}
			state := "succeeded"
			message := ""
			if err != nil {
				message = safeError(err)
				var network net.Error
				var remote *dns.RemoteError
				if errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &remote) && remote.UnknownResult) {
					state = "unknown"
					unknown++
				} else {
					state = "failed"
					failed++
				}
			} else {
				success++
			}
			detail, _ = json.Marshal(map[string]any{"domain_id": id, "record": result, "message": message})
			if e := r.Store.SaveJobItem(ctx, j, store.JobItem{Index: index, ResourceID: record.ID, State: state, Detail: detail}); e != nil {
				return nil, e
			}
			if e := r.Store.AddJobEvent(ctx, j, "info", fmt.Sprintf("第%d项：%s", index+1, state), map[string]any{"item": index, "domain_id": id, "state": state}); e != nil {
				return nil, e
			}
		}
	}
	result := map[string]int{"succeeded": success, "failed": failed, "unknown": unknown}
	if unknown > 0 {
		return result, &UnknownError{Message: "部分外部操作结果需要核对"}
	}
	if failed > 0 {
		return result, &PartialError{Message: "部分记录变更失败"}
	}
	return result, nil
}

type ScheduleData struct {
	RecordID  string     `json:"record_id"`
	Operation string     `json:"operation"`
	Record    dns.Record `json:"record"`
	Schedule  Schedule   `json:"schedule"`
}

func (r *Runner) schedule(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d ScheduleData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	p, err := r.principal(ctx, j)
	if err != nil {
		return nil, err
	}
	_, provider, err := r.provider(ctx, p, o.DomainID, "dns:write")
	if err != nil {
		return nil, err
	}
	if err = r.check(ctx, j); err != nil {
		return nil, err
	}
	record, err := r.recordForMutation(ctx, j, provider, d.RecordID)
	if err != nil {
		return nil, err
	}
	switch d.Operation {
	case "enable":
		record, err = r.mutateDNS(ctx, j, provider, 0, "enable", record)
	case "disable":
		record, err = r.mutateDNS(ctx, j, provider, 0, "disable", record)
	case "delete":
		record, err = r.mutateDNS(ctx, j, provider, 0, "delete", record)
	case "update":
		if d.Record.Value != "" {
			record.Value = d.Record.Value
			record.Values = nil
		}
		if d.Record.Type != "" {
			record.Type = d.Record.Type
		}
		if d.Record.Line != "" {
			record.Line = d.Record.Line
		}
		if d.Record.TTL > 0 {
			record.TTL = d.Record.TTL
		}
		record.Proxied = d.Record.Proxied
		if len(d.Record.Values) > 0 {
			record.Values = d.Record.Values
			record.Value = d.Record.Values[0]
		}
		if d.Record.Priority != nil {
			record.Priority = d.Record.Priority
		}
		if d.Record.Weight != nil {
			record.Weight = d.Record.Weight
		}
		record, err = r.mutateDNS(ctx, j, provider, 0, "update", record)
	default:
		err = errors.New("invalid schedule operation")
	}
	if err != nil {
		return nil, err
	}
	if record.ID != "" && record.ID != d.RecordID && d.Operation != "delete" {
		if _, err = r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"record_id": record.ID}, "", nil); err != nil {
			return nil, err
		}
	}
	r.Store.Audit(ctx, j.OwnerID, "schedule."+d.Operation, "record", d.RecordID, o.DomainID, "", map[string]string{"job_id": j.ID})
	return map[string]any{"record": record, "operation": d.Operation}, nil
}

type MonitorData struct {
	RecordID string `json:"record_id"`
	Name     string `json:"name"`
	ProbeSpec
	FrequencySeconds   int          `json:"frequency_seconds"`
	Failures           int          `json:"failures"`
	Recoveries         int          `json:"recoveries"`
	Mode               string       `json:"mode"`
	MainValue          string       `json:"main_value"`
	BackupValue        string       `json:"backup_value"`
	Proxied            bool         `json:"proxied"`
	ConditionIDs       []string     `json:"condition_ids"`
	ConditionThreshold int          `json:"condition_threshold"`
	State              MonitorState `json:"state"`
}
type MonitorState struct {
	Healthy               *bool       `json:"healthy"`
	ConsecutiveFailures   int         `json:"consecutive_failures"`
	ConsecutiveRecoveries int         `json:"consecutive_recoveries"`
	Switched              bool        `json:"switched"`
	LastProbe             ProbeResult `json:"last_probe"`
	LastSwitch            time.Time   `json:"last_switch,omitempty"`
	Desired               string      `json:"desired,omitempty"`
	Observed              string      `json:"observed,omitempty"`
}

func (r *Runner) monitor(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d MonitorData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	var payload struct {
		Action string `json:"action"`
	}
	json.Unmarshal(j.Payload, &payload)
	if d.Mode != "conditional" && d.Proxy && d.ProxyURL == "" {
		var network struct {
			URL string `json:"proxy_url"`
		}
		if err = r.Store.Setting(ctx, "network", &network); err != nil {
			return nil, err
		}
		d.ProbeSpec.ProxyURL = network.URL
		if network.URL == "" {
			return nil, errors.New("检测已启用代理，但网络代理尚未配置")
		}
	}
	var result ProbeResult
	if d.Mode == "conditional" {
		healthy := 0
		for _, id := range d.ConditionIDs {
			other, e := r.Store.Object(ctx, id)
			if e != nil || other.Kind != "monitors" || !other.Active {
				continue
			}
			var state MonitorData
			if json.Unmarshal(other.Data, &state) == nil && state.State.Healthy != nil && *state.State.Healthy && time.Since(state.State.LastProbe.CheckedAt) <= time.Duration(max(state.FrequencySeconds*3, 15))*time.Second {
				healthy++
			}
		}
		result = ProbeResult{Healthy: healthy > d.ConditionThreshold, CheckedAt: time.Now().UTC()}
	} else {
		result = Probe(ctx, d.ProbeSpec)
	}
	if payload.Action == "test" {
		return result, nil
	} // manual probe has no failover side effect
	if d.Failures < 1 {
		d.Failures = 3
	}
	if d.Recoveries < 1 {
		d.Recoveries = 3
	}
	d.State.LastProbe = result
	shouldSwitch := d.State.Switched
	var event any
	eventKey := ""
	if d.Mode == "conditional" {
		shouldSwitch = !result.Healthy
	} else if result.Healthy {
		d.State.ConsecutiveFailures = 0
		d.State.ConsecutiveRecoveries++
		if d.State.Switched && d.State.ConsecutiveRecoveries >= d.Recoveries {
			shouldSwitch = false
		}
	} else {
		d.State.ConsecutiveRecoveries = 0
		d.State.ConsecutiveFailures++
		if !d.State.Switched && d.State.ConsecutiveFailures >= d.Failures {
			shouldSwitch = true
		}
	}
	d.State.Healthy = &result.Healthy
	var transition struct {
		Pending  bool         `json:"pending"`
		Switched bool         `json:"switched"`
		State    MonitorState `json:"state"`
	}
	if len(j.Checkpoint) > 0 && json.Unmarshal(j.Checkpoint, &transition) == nil && transition.Pending {
		shouldSwitch = transition.Switched
		d.State = transition.State
	}
	if shouldSwitch != d.State.Switched {
		d.State.Desired = map[bool]string{true: "backup", false: "main"}[shouldSwitch]
		if !transition.Pending {
			transition.Pending = true
			transition.Switched = shouldSwitch
			transition.State = d.State
			if err = r.Store.CheckpointJob(ctx, j, transition); err != nil {
				return nil, err
			}
		}
		if d.Mode != "notify" {
			p, e := r.principal(ctx, j)
			if e != nil {
				return nil, e
			}
			_, provider, e := r.provider(ctx, p, o.DomainID, "dns:write")
			if e != nil {
				return nil, e
			}
			if e = r.check(ctx, j); e != nil {
				return nil, e
			}
			record, e := r.recordForMutation(ctx, j, provider, d.RecordID)
			if e != nil {
				return nil, e
			}
			if d.Mode == "disable" || d.Mode == "conditional" {
				enabled := !shouldSwitch
				if d.Mode == "conditional" {
					enabled = shouldSwitch
				}
				operation := "disable"
				if enabled {
					operation = "enable"
				}
				record, e = r.mutateDNS(ctx, j, provider, 0, operation, record)
			} else {
				record.Value = d.MainValue
				if shouldSwitch {
					record.Value = d.BackupValue
				}
				record.Type = valueType(record.Value)
				record.Values = nil
				record.Proxied = d.Proxied
				record, e = r.mutateDNS(ctx, j, provider, 0, "update", record)
			}
			if e != nil {
				r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"state": d.State}, "", nil)
				return nil, e
			}
			if record.ID != "" {
				d.RecordID = record.ID
			}
		}
		d.State.Switched = shouldSwitch
		d.State.Observed = d.State.Desired
		d.State.LastSwitch = time.Now().UTC()
		eventKey = "monitor:" + o.ID + ":" + j.ID
		event = notifications.Message{Title: "DNS容灾状态发生切换", Body: map[bool]string{true: "记录已切换到备用状态。", false: "记录已恢复主状态。"}[shouldSwitch], Event: map[bool]string{true: "monitor.alert", false: "monitor.recovered"}[shouldSwitch], ResourceID: o.ID, Data: map[string]any{"switched": shouldSwitch, "domain_id": o.DomainID, "job_id": j.ID}}
		r.Store.AddJobEvent(ctx, j, "info", "容灾状态发生切换", map[string]any{"switched": shouldSwitch})
		r.Store.Audit(ctx, j.OwnerID, "monitor.switch", "monitor", o.ID, o.DomainID, "", map[string]any{"switched": shouldSwitch, "job_id": j.ID})
	}
	if _, err = r.Store.SaveObjectRuntime(ctx, o, j, map[string]any{"state": d.State, "record_id": d.RecordID}, eventKey, event); err != nil {
		return nil, err
	}
	return d.State, nil
}
func valueType(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return "CNAME"
	}
	if ip.To4() != nil {
		return "A"
	}
	return "AAAA"
}
func safeError(err error) string {
	message := err.Error()
	if strings.Contains(message, "http://") || strings.Contains(message, "https://") {
		return "remote connection or request failed"
	}
	if len(message) > 500 {
		message = message[:500]
	}
	return message
}
func (r *Runner) Tick(ctx context.Context) error {
	if err := r.QueueTerminalEvents(ctx); err != nil {
		return err
	}
	if err := r.certificateExpiry(ctx); err != nil {
		return err
	}
	for _, kind := range []string{"monitors", "schedules", "optimizations", "certificates", "deployments"} {
		objects, err := r.Store.Objects(ctx, kind)
		if err != nil {
			return err
		}
		for _, o := range objects {
			if !o.Active {
				continue
			}
			var data map[string]any
			if json.Unmarshal(o.Data, &data) != nil {
				continue
			}
			mode := Schedule{Mode: "interval", IntervalSeconds: 60}
			switch kind {
			case "schedules":
				var d ScheduleData
				if json.Unmarshal(o.Data, &d) != nil {
					continue
				}
				mode = d.Schedule
			case "monitors":
				n, _ := data["frequency_seconds"].(float64)
				mode.IntervalSeconds = int(n)
				if mode.IntervalSeconds < 5 {
					mode.IntervalSeconds = 5
				}
			case "optimizations":
				n, _ := data["interval_seconds"].(float64)
				mode.IntervalSeconds = int(n)
				if mode.IntervalSeconds < 600 {
					mode.IntervalSeconds = 600
				}
			case "certificates":
				auto, _ := data["auto_renew"].(bool)
				if !auto {
					continue
				}
				expires, _ := data["not_after"].(string)
				date, e := time.Parse(time.RFC3339, expires)
				if e != nil {
					continue
				}
				days, _ := data["renew_before_days"].(float64)
				if days < 1 {
					days = 30
				}
				if time.Until(date) > time.Duration(days)*24*time.Hour {
					continue
				}
				mode.IntervalSeconds = 3600
			case "deployments":
				auto, _ := data["auto_deploy"].(bool)
				if !auto {
					continue
				}
				certID, _ := data["certificate_id"].(string)
				certificate, e := r.Store.Object(ctx, certID)
				if e != nil {
					continue
				}
				var c map[string]any
				json.Unmarshal(certificate.Data, &c)
				if c["fingerprint"] == nil || c["fingerprint"] == data["deployed_fingerprint"] {
					continue
				}
				mode.IntervalSeconds = 300
			}
			if err = r.enqueueDue(ctx, o, mode); err != nil && !store.IsDuplicate(err) {
				return err
			}
		}
	}
	return nil
}
func (r *Runner) enqueueDue(ctx context.Context, o store.Object, s Schedule) error {
	now := time.Now().UTC()
	release, err := r.Store.LockResources(ctx, []string{"schedule:" + o.ID, "object:" + o.ID})
	if errors.Is(err, store.ErrResourceBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	current, e := r.Store.Object(ctx, o.ID)
	if e != nil {
		return e
	}
	if !current.Active || current.ConfigVersion != o.ConfigVersion {
		return nil
	}
	var next sql.NullTime
	var revision int64
	err = r.Store.DB.QueryRowContext(ctx, "SELECT next_run_at,revision FROM object_schedule_state WHERE object_id=?", o.ID).Scan(&next, &revision)
	if errors.Is(err, sql.ErrNoRows) || revision != o.ConfigVersion {
		anchor := o.UpdatedAt
		if anchor.IsZero() || anchor.After(now) {
			anchor = now
		}
		if s.Mode == "once" {
			anchor = now.AddDate(-100, 0, 0)
		}
		due, e := s.Next(anchor.Add(-time.Nanosecond))
		if e != nil {
			return e
		}
		if s.Mode == "interval" {
			due = now
		}
		_, e = r.Store.DB.ExecContext(ctx, "INSERT INTO object_schedule_state(object_id,next_run_at,revision) VALUES (?,?,?) ON DUPLICATE KEY UPDATE next_run_at=VALUES(next_run_at),revision=VALUES(revision)", o.ID, nullableTime(due), o.ConfigVersion)
		if e != nil {
			return e
		}
		next = sql.NullTime{Time: due, Valid: !due.IsZero()}
	} else if err != nil {
		return err
	}
	if !next.Valid || next.Time.After(now) {
		return nil
	}
	// Calendar rules tolerate one scheduler minute. Older occurrences follow
	// the configured recovery policy; run_once never replays a backlog.
	if o.Kind == "schedules" && s.MissedPolicy != "run_once" && now.Sub(next.Time) > time.Minute {
		future, e := s.Next(now)
		if e != nil {
			return e
		}
		_, e = r.Store.DB.ExecContext(ctx, "UPDATE object_schedule_state SET next_run_at=? WHERE object_id=? AND revision=?", nullableTime(future), o.ID, o.ConfigVersion)
		return e
	}
	var running int
	if err = r.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM jobs WHERE resource_id=? AND state IN ('queued','running','retry','unknown')", o.ID).Scan(&running); err != nil {
		return err
	}
	if running > 0 {
		return nil
	}
	action := "execute"
	if o.Kind == "certificates" {
		action = "renew"
	}
	raw, _ := json.Marshal(map[string]any{"action": action, "scheduled": true, "config_version": o.ConfigVersion})
	maxAttempts := 3
	if o.Kind == "deployments" {
		var d DeploymentData
		json.Unmarshal(o.Data, &d)
		policy, e := NormalizeDeploymentRetryPolicy(d.RetryPolicy)
		if e != nil {
			return e
		}
		maxAttempts = policy.MaxAttempts
	}
	_, err = r.Store.CreateJob(ctx, store.Job{Kind: o.Kind, ResourceID: o.ID, OwnerID: o.OwnerID, DomainID: o.DomainID, Payload: raw, MaxAttempts: maxAttempts, OccurrenceKey: o.ID + ":" + next.Time.UTC().Format(time.RFC3339Nano)})
	if err != nil && !store.IsDuplicate(err) {
		return err
	}
	future, err := s.Next(now)
	if err != nil {
		return err
	}
	_, err = r.Store.DB.ExecContext(ctx, "UPDATE object_schedule_state SET next_run_at=?,last_run_at=UTC_TIMESTAMP(6),revision=? WHERE object_id=?", nullableTime(future), o.ConfigVersion, o.ID)
	return err
}
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
