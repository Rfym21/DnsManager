package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

// Recovery reuses the original job and its durable item intents. Successful
// mutations cannot be submitted again through a new batch by accident.
func (a *API) recoveryJob(w http.ResponseWriter, r *http.Request) (store.Job, func(), bool) {
	j, ok := a.authorizedJob(w, r)
	if !ok {
		return j, nil, false
	}
	p := principal(r)
	if !p.AllowsScope("dns:write") && !p.AllowsScope("admin") {
		a.fail(w, r, 403, "forbidden", "没有任务恢复权限")
		return j, nil, false
	}
	if j.Kind != "record_batch" && (!p.Admin() || !p.AllowsScope("admin")) {
		a.fail(w, r, 403, "forbidden", "此任务需管理员恢复")
		return j, nil, false
	}
	keys := []string{"job:" + j.ID}
	if j.ResourceID != "" {
		keys = append(keys, "object:"+j.ResourceID)
	}
	var payload struct {
		DomainIDs []string `json:"domain_ids"`
	}
	json.Unmarshal(j.Payload, &payload)
	if j.DomainID != "" {
		payload.DomainIDs = append(payload.DomainIDs, j.DomainID)
	}
	for _, id := range payload.DomainIDs {
		if !a.authorizeDomain(w, r, id, "dns:write") {
			return j, nil, false
		}
		d, err := a.Store.Domain(r.Context(), id)
		if err != nil {
			a.internal(w, r, err)
			return j, nil, false
		}
		keys = append(keys, "dns-account:"+d.AccountID)
	}
	release, err := a.Store.LockResources(r.Context(), keys)
	if err != nil {
		a.internal(w, r, err)
		return j, nil, false
	}
	j, err = a.Store.Job(r.Context(), j.ID)
	if err != nil {
		release()
		a.internal(w, r, err)
		return j, nil, false
	}
	if j.State != "failed" && j.State != "partial" && j.State != "unknown" {
		release()
		a.fail(w, r, 409, "not_recoverable", "任务当前状态不能恢复")
		return j, nil, false
	}
	return j, release, true
}

func (a *API) reconcileJob(w http.ResponseWriter, r *http.Request) {
	j, release, ok := a.recoveryJob(w, r)
	if !ok {
		return
	}
	defer release()
	if j.Kind != "record_batch" && j.Kind != "schedules" && j.Kind != "monitors" && j.Kind != "optimizations" {
		a.fail(w, r, 422, "reconcile_unavailable", "此任务请使用已有检查点重试；DNS验证结果会在恢复时核对")
		return
	}
	if err := a.reconcileDNSJob(r.Context(), j); err != nil {
		a.internal(w, r, err)
		return
	}
	a.job(w, r)
}

func (a *API) retryJob(w http.ResponseWriter, r *http.Request) {
	j, release, ok := a.recoveryJob(w, r)
	if !ok {
		return
	}
	defer release()
	if j.Kind == "record_batch" || j.Kind == "schedules" || j.Kind == "monitors" || j.Kind == "optimizations" {
		if err := a.reconcileDNSJob(r.Context(), j); err != nil {
			a.internal(w, r, err)
			return
		}
		items, err := a.Store.JobItems(r.Context(), j.ID)
		if err != nil {
			a.internal(w, r, err)
			return
		}
		for _, item := range items {
			if item.State == "unknown" || item.State == "running" {
				a.fail(w, r, 409, "result_unknown", "仍有外部结果未知的项目，请核对后再恢复")
				return
			}
		}
	} else if j.State == "unknown" && j.Kind != "certificates" {
		a.fail(w, r, 409, "result_unknown", "外部结果未知，请先在目标平台核对已有变更")
		return
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM job_items WHERE job_id=? AND state='failed'", j.ID); err != nil {
		a.internal(w, r, err)
		return
	}
	result, err := tx.ExecContext(r.Context(), "UPDATE jobs SET state='queued',attempt=0,cancel_requested=FALSE,error_code='',error_message='',next_run_at=UTC_TIMESTAMP(6),lease_owner=NULL,lease_until=NULL,completed=(SELECT COUNT(*) FROM job_items WHERE job_id=? AND state='succeeded'),updated_at=UTC_TIMESTAMP(6) WHERE id=? AND state IN ('failed','partial','unknown')", j.ID, j.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		a.internal(w, r, store.ErrConflict)
		return
	}
	if err = tx.Commit(); err != nil {
		a.internal(w, r, err)
		return
	}
	a.Store.Audit(r.Context(), principal(r).User.ID, "job.retry", "job", j.ID, j.DomainID, "", map[string]any{"preserved_checkpoint": true})
	j, err = a.Store.Job(r.Context(), j.ID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	j.Result = redactJSON(j.Result)
	send(w, 202, map[string]any{"job": j})
}

func (a *API) reconcileDNSJob(ctx context.Context, j store.Job) error {
	if j.Kind == "record_batch" {
		return a.reconcileBatch(ctx, j)
	}
	d, err := a.Store.Domain(ctx, j.DomainID)
	if err != nil {
		return err
	}
	account, err := a.Store.Account(ctx, d.AccountID)
	if err != nil {
		return err
	}
	p, err := a.DNSFactory(account.Provider, account.Config, d.ProviderDomainID, d.ASCIIName)
	if err != nil {
		return err
	}
	items, err := a.Store.JobItems(ctx, j.ID)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.State != "running" && item.State != "unknown" {
			continue
		}
		var intent struct {
			Operation string     `json:"operation"`
			Record    dns.Record `json:"record"`
			Result    dns.Record `json:"result"`
		}
		if json.Unmarshal(item.Detail, &intent) != nil || intent.Operation == "" {
			return errors.New("invalid DNS intent")
		}
		observed, confirmed, e := dns.ObserveMutation(ctx, p, intent.Operation, intent.Record)
		if e != nil {
			return e
		}
		if !confirmed {
			continue
		}
		intent.Result = observed
		detail, _ := json.Marshal(intent)
		enc, e := a.Store.Box.Seal("job-item:"+j.ID+":"+strconv.Itoa(item.Index), detail)
		if e != nil {
			return e
		}
		if _, e = a.Store.DB.ExecContext(ctx, "UPDATE job_items SET state='succeeded',detail_ciphertext=?,updated_at=UTC_TIMESTAMP(6) WHERE job_id=? AND item_index=? AND state IN ('running','unknown')", enc, j.ID, item.Index); e != nil {
			return e
		}
	}
	_, err = a.Store.DB.ExecContext(ctx, "UPDATE jobs SET completed=(SELECT COUNT(*) FROM job_items WHERE job_id=? AND state='succeeded'),updated_at=UTC_TIMESTAMP(6) WHERE id=?", j.ID, j.ID)
	return err
}

func (a *API) reconcileBatch(ctx context.Context, j store.Job) error {
	var payload struct {
		DomainIDs []string     `json:"domain_ids"`
		Records   []dns.Record `json:"records"`
		Operation string       `json:"operation"`
	}
	if json.Unmarshal(j.Payload, &payload) != nil || len(payload.Records) == 0 {
		return errors.New("invalid saved batch")
	}
	items, err := a.Store.JobItems(ctx, j.ID)
	if err != nil {
		return err
	}
	providers := map[string]dns.Provider{}
	for _, item := range items {
		if item.State != "running" && item.State != "unknown" {
			continue
		}
		domainIndex, recordIndex := item.Index/len(payload.Records), item.Index%len(payload.Records)
		if domainIndex < 0 || domainIndex >= len(payload.DomainIDs) {
			return errors.New("invalid saved item index")
		}
		id := payload.DomainIDs[domainIndex]
		p := providers[id]
		if p == nil {
			d, e := a.Store.Domain(ctx, id)
			if e != nil {
				return e
			}
			account, e := a.Store.Account(ctx, d.AccountID)
			if e != nil {
				return e
			}
			p, e = a.DNSFactory(account.Provider, account.Config, d.ProviderDomainID, d.ASCIIName)
			if e != nil {
				return e
			}
			providers[id] = p
		}
		record := payload.Records[recordIndex]
		observed, confirmed, e := dns.ObserveMutation(ctx, p, payload.Operation, record)
		if e != nil {
			return e
		}
		state := "unknown"
		if confirmed {
			state = "succeeded"
		}
		detail, _ := json.Marshal(map[string]any{"domain_id": id, "record": observed, "message": map[bool]string{true: "只读核对确认已完成", false: "平台结果尚未唯一确认"}[confirmed]})
		enc, e := a.Store.Box.Seal("job-item:"+j.ID+":"+strconv.Itoa(item.Index), detail)
		if e != nil {
			return e
		}
		if _, e = a.Store.DB.ExecContext(ctx, "UPDATE job_items SET state=?,detail_ciphertext=?,updated_at=UTC_TIMESTAMP(6) WHERE job_id=? AND item_index=? AND state IN ('running','unknown')", state, enc, j.ID, item.Index); e != nil {
			return e
		}
	}
	_, err = a.Store.DB.ExecContext(ctx, "UPDATE jobs SET completed=(SELECT COUNT(*) FROM job_items WHERE job_id=? AND state IN ('succeeded','failed','unknown','skipped')),updated_at=UTC_TIMESTAMP(6) WHERE id=?", j.ID, j.ID)
	return err
}

func sameDesiredRecord(a, b dns.Record) bool {
	return dns.DesiredEqual(a, b)
}
