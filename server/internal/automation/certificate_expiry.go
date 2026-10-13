package automation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

// Expiry reminders also cover manually imported certificates. The event key
// identifies the certificate generation, so retries and concurrent schedulers
// do not send a second notice for the same certificate.
func (r *Runner) certificateExpiry(ctx context.Context) error {
	var site struct {
		Timezone string `json:"timezone"`
		Days     int    `json:"certificate_renew_before_days"`
	}
	if err := r.Store.Setting(ctx, "site", &site); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if site.Days < 1 {
		site.Days = 7
	}
	if site.Timezone == "" {
		site.Timezone = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(site.Timezone)
	if err != nil {
		return err
	}
	objects, err := r.Store.Objects(ctx, "certificates")
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, object := range objects {
		var data CertificateData
		if json.Unmarshal(object.Data, &data) != nil {
			continue
		}
		if _, _, eligible := certificateExpiryMessage(object, data, now, site.Days, loc); !eligible {
			continue
		}
		if err = r.queueCertificateExpiry(ctx, object.ID, now, site.Days, loc); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) queueCertificateExpiry(ctx context.Context, id string, now time.Time, defaultDays int, loc *time.Location) error {
	tx, err := r.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var object store.Object
	var encrypted string
	// Re-read under a row lock: a renewal or deletion between the scan and
	// enqueue must not produce a notice for an obsolete certificate.
	err = tx.QueryRowContext(ctx, "SELECT id,name,active,data_ciphertext FROM objects WHERE id=? AND kind='certificates' FOR UPDATE", id).Scan(&object.ID, &object.Name, &object.Active, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var data CertificateData
	if err = r.Store.Decrypt("object:"+id, encrypted, &data); err != nil {
		return err
	}
	key, message, eligible := certificateExpiryMessage(object, data, now, defaultDays, loc)
	if !eligible {
		return nil
	}
	if err = r.Store.QueueBusinessEventTx(ctx, tx, key, message); err != nil {
		return err
	}
	return tx.Commit()
}

func certificateExpiryMessage(object store.Object, data CertificateData, now time.Time, defaultDays int, loc *time.Location) (string, notifications.Message, bool) {
	if !object.Active || data.NotAfter.IsZero() || !data.NotAfter.After(now) || data.NotBefore.After(now) || data.Status == "revoked" || data.Status == "cancelled" {
		return "", notifications.Message{}, false
	}
	days := data.RenewBeforeDays
	if days < 1 {
		days = defaultDays
	}
	if days < 1 {
		days = 7
	}
	if data.NotAfter.Sub(now).Hours()/24 > float64(days) {
		return "", notifications.Message{}, false
	}
	if loc == nil {
		loc = time.UTC
	}
	remaining := int(math.Ceil(data.NotAfter.Sub(now).Hours() / 24))
	names := strings.Join(data.Domains, ", ")
	if names == "" {
		names = object.Name
	}
	message := notifications.Message{
		Title: "SSL证书即将到期提醒",
		Body:  fmt.Sprintf("%s 的SSL证书将于 %s 到期，剩余 %d 天，请确认续期和部署状态。", names, data.NotAfter.In(loc).Format("2006-01-02 15:04:05 MST"), remaining),
		Event: "certificate.expiring", ResourceID: object.ID,
		Data: map[string]any{"certificate_id": object.ID, "domains": data.Domains, "issuer": data.Issuer, "not_before": data.NotBefore, "not_after": data.NotAfter, "auto_renew": data.AutoRenew, "days_remaining": remaining, "renew_before_days": days},
	}
	generation := sha256.Sum256([]byte(data.Fingerprint + "\x00" + data.NotAfter.UTC().Format(time.RFC3339Nano)))
	return "certificate-expiry:" + object.ID + ":" + hex.EncodeToString(generation[:]), message, true
}
