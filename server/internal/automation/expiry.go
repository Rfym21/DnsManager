package automation

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/dns-manager/dnsmgr/server/internal/domaininfo"
	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"strconv"
	"strings"
	"time"
)

var registryLookup domaininfo.Lookup

// Refreshes bounded batches. Unknown registry dates never replace known dates
// or produce an expired-domain notice. Events and notice timestamps commit together.
func (r *Runner) domainExpiry(ctx context.Context) error {
	var site struct {
		Timezone string `json:"timezone"`
		Days     string `json:"domain_expiry_days"`
	}
	if err := r.Store.Setting(ctx, "site", &site); err != nil && err != sql.ErrNoRows {
		return err
	}
	days := map[int]bool{}
	for _, v := range strings.Split(site.Days, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil && n >= 0 && n <= 365 {
			days[n] = true
		}
	}
	if len(days) == 0 {
		return nil
	}
	rows, err := r.Store.DB.QueryContext(ctx, "SELECT id,ascii_name FROM domains WHERE expiry_notice_enabled=TRUE AND (expiry_checked_at IS NULL OR expiry_checked_at<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 DAY)) ORDER BY COALESCE(expiry_checked_at,'1970-01-01') LIMIT 5")
	if err != nil {
		return err
	}
	type item struct{ id, name string }
	items := []item{}
	for rows.Next() {
		var v item
		if err = rows.Scan(&v.id, &v.name); err != nil {
			rows.Close()
			return err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range items {
		release, lockErr := r.Store.LockResources(ctx, []string{"domain-expiry:" + v.id})
		if lockErr != nil {
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		dates, e := registryLookup.Resolve(lookupCtx, v.name)
		cancel()
		if e == nil {
			_, err = r.Store.DB.ExecContext(ctx, "UPDATE domains SET registered_at=COALESCE(?,registered_at),expires_at=COALESCE(?,expires_at),expiry_checked_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP(6) WHERE id=?", dates.RegisteredAt, dates.ExpiresAt, v.id)
		} else {
			_, err = r.Store.DB.ExecContext(ctx, "UPDATE domains SET expiry_checked_at=UTC_TIMESTAMP() WHERE id=?", v.id)
		}
		release()
		if err != nil {
			return err
		}
	}
	zone := site.Timezone
	if zone == "" {
		zone = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return err
	}
	now := time.Now().In(loc)
	if now.Hour() < 9 {
		return nil
	}
	// Locks coordinate multiple schedulers and prevent duplicate daily notices.
	tx, err := r.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err = tx.QueryContext(ctx, "SELECT id,name,expires_at FROM domains WHERE expiry_notice_enabled=TRUE AND expires_at>=UTC_TIMESTAMP() AND expires_at<DATE_ADD(UTC_TIMESTAMP(),INTERVAL 366 DAY) AND (expiry_notice_at IS NULL OR expiry_notice_at<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 20 HOUR)) ORDER BY expires_at LIMIT 200 FOR UPDATE SKIP LOCKED")
	if err != nil {
		return err
	}
	type notice struct {
		id, name string
		expiry   time.Time
	}
	notices := []notice{}
	for rows.Next() {
		var v notice
		if err = rows.Scan(&v.id, &v.name, &v.expiry); err != nil {
			rows.Close()
			return err
		}
		if days[int(v.expiry.Sub(now).Hours()/24)] {
			notices = append(notices, v)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range notices {
		message := notifications.Message{Title: "域名到期提醒", Body: fmt.Sprintf("%s 将于 %s 到期，请确认续费状态。", v.name, v.expiry.In(loc).Format("2006-01-02")), Event: "domain.expiring", ResourceID: v.id, Data: map[string]any{"domain_id": v.id, "expires_at": v.expiry}}
		if err = r.Store.QueueBusinessEventTx(ctx, tx, "expiry:"+v.id+":"+now.Format("2006-01-02"), message); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE domains SET expiry_notice_at=UTC_TIMESTAMP() WHERE id=?", v.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
