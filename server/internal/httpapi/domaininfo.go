package httpapi

import (
	"context"
	"database/sql"
	"github.com/dns-manager/dnsmgr/server/internal/domaininfo"
	"github.com/go-chi/chi/v5"
	"net/http"
	"time"
)

var registryLookup domaininfo.Lookup

func (a *API) domainDates(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !a.authorizeDomain(w, r, id, "dns:read") {
		return
	}
	var registered, expires, checked, noticed sql.NullTime
	var enabled bool
	if err := a.Store.DB.QueryRowContext(r.Context(), "SELECT registered_at,expires_at,expiry_checked_at,expiry_notice_at,expiry_notice_enabled FROM domains WHERE id=?", id).Scan(&registered, &expires, &checked, &noticed, &enabled); err != nil {
		a.internal(w, r, err)
		return
	}
	values := map[string]any{"expiry_notice_enabled": enabled}
	for key, value := range map[string]sql.NullTime{"registered_at": registered, "expires_at": expires, "checked_at": checked, "notice_at": noticed} {
		if value.Valid {
			values[key] = value.Time
		} else {
			values[key] = nil
		}
	}
	send(w, 200, values)
}
func (a *API) refreshDomainDates(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !a.authorizeDomain(w, r, id, "dns:write") {
		return
	}
	d, err := a.Store.Domain(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	dates, err := registryLookup.Resolve(ctx, d.ASCIIName)
	if err != nil {
		a.Store.DB.ExecContext(r.Context(), "UPDATE domains SET expiry_checked_at=UTC_TIMESTAMP() WHERE id=?", id)
		a.fail(w, r, 502, "registry_unavailable", "注册局未提供有效到期日期，请稍后重试或手动设置")
		return
	}
	tx, err := a.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), "UPDATE domains SET registered_at=COALESCE(?,registered_at),expires_at=COALESCE(?,expires_at),expiry_checked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP(6) WHERE id=?", dates.RegisteredAt, dates.ExpiresAt, id)
	if err == nil {
		_, err = tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor_id,action,resource_type,resource_id,domain_id,request_id,detail,created_at) VALUES(?,'domain.dates.refresh','domain',?,?,'',JSON_OBJECT(),UTC_TIMESTAMP(6))", principal(r).User.ID, id, id)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, dates)
}

func (a *API) saveDomainDates(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !a.authorizeDomain(w, r, id, "dns:write") {
		return
	}
	var req struct {
		Enabled    *bool   `json:"expiry_notice_enabled"`
		Registered *string `json:"registered_at"`
		Expires    *string `json:"expires_at"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	parse := func(value *string) (any, error) {
		if value == nil || *value == "" {
			return nil, nil
		}
		t, e := time.Parse("2006-01-02", *value)
		if e != nil {
			t, e = time.Parse(time.RFC3339, *value)
		}
		return t, e
	}
	registered, e := parse(req.Registered)
	if e != nil {
		a.fail(w, r, 400, "invalid_date", "注册日期不正确")
		return
	}
	expires, e := parse(req.Expires)
	if e != nil {
		a.fail(w, r, 400, "invalid_date", "到期日期不正确")
		return
	}
	if req.Registered != nil && req.Expires != nil && registered != nil && expires != nil && expires.(time.Time).Before(registered.(time.Time)) {
		a.fail(w, r, 400, "invalid_date", "到期日期不能早于注册日期")
		return
	}
	tx, e := a.Store.DB.BeginTx(r.Context(), nil)
	if e != nil {
		a.internal(w, r, e)
		return
	}
	defer tx.Rollback()
	var existingRegistered, existingExpires sql.NullTime
	if e = tx.QueryRowContext(r.Context(), "SELECT registered_at,expires_at FROM domains WHERE id=? FOR UPDATE", id).Scan(&existingRegistered, &existingExpires); e != nil {
		a.internal(w, r, e)
		return
	}
	if req.Registered == nil && existingRegistered.Valid {
		registered = existingRegistered.Time
	}
	if req.Expires == nil && existingExpires.Valid {
		expires = existingExpires.Time
	}
	if registered != nil && expires != nil && expires.(time.Time).Before(registered.(time.Time)) {
		a.fail(w, r, 400, "invalid_date", "到期日期不能早于注册日期")
		return
	}
	if req.Enabled != nil {
		_, e = tx.ExecContext(r.Context(), "UPDATE domains SET expiry_notice_enabled=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", *req.Enabled, id)
	}
	if e == nil && req.Registered != nil {
		_, e = tx.ExecContext(r.Context(), "UPDATE domains SET registered_at=?,updated_at=UTC_TIMESTAMP(6) WHERE id=?", registered, id)
	}
	if e == nil && req.Expires != nil {
		_, e = tx.ExecContext(r.Context(), "UPDATE domains SET expires_at=?,expiry_checked_at=UTC_TIMESTAMP(),expiry_notice_at=NULL,updated_at=UTC_TIMESTAMP(6) WHERE id=?", expires, id)
	}
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor_id,action,resource_type,resource_id,domain_id,request_id,detail,created_at) VALUES(?,'domain.dates.update','domain',?,?,'',JSON_OBJECT(),UTC_TIMESTAMP(6))", principal(r).User.ID, id, id)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		a.internal(w, r, e)
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
