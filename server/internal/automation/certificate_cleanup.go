package automation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
)

// A DNS write can finish before the issuer saves Presented and its receipt.
// Cancellation therefore reconciles the durable write intents as well.
func (c *challengeDNS) cleanupResourceIntents(ctx context.Context) error {
	rows, err := c.runner.Store.DB.QueryContext(ctx, "SELECT i.job_id,i.challenge_key,i.domain_id,i.intent_ciphertext,i.record_id FROM dns_challenge_intents i JOIN jobs j ON j.id=i.job_id WHERE j.resource_id=? AND i.state<>'cleaned' ORDER BY i.created_at", c.job.ResourceID)
	if err != nil {
		return err
	}
	type intent struct{ job, key, domain, encrypted, record string }
	items := []intent{}
	for rows.Next() {
		var item intent
		if err = rows.Scan(&item.job, &item.key, &item.domain, &item.encrypted, &item.record); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	p, err := c.runner.principal(ctx, c.job)
	if err != nil {
		return err
	}
	for _, item := range items {
		var planned struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if err = c.runner.Store.Decrypt("dns-intent:"+item.job+":"+item.key, item.encrypted, &planned); err != nil {
			return err
		}
		_, provider, err := c.runner.provider(ctx, p, item.domain, "dns:write")
		if err != nil {
			return err
		}
		var record dns.Record
		if item.record != "" {
			record, err = provider.GetRecord(ctx, item.record)
			if err != nil && !errors.Is(err, dns.ErrNotFound) {
				return err
			}
		} else {
			found := 0
			listed := 0
			for page := 1; page <= 200; page++ {
				result, err := provider.ListRecords(ctx, dns.ListOptions{Name: planned.Name, Type: planned.Type, Page: page, PageSize: 100})
				if err != nil {
					return err
				}
				for _, current := range result.Rows {
					if current.Name == planned.Name && strings.EqualFold(current.Type, planned.Type) && current.Value == planned.Value {
						found++
						record = current
					}
				}
				listed += len(result.Rows)
				if result.Total > 0 && listed >= result.Total || result.Total == 0 && len(result.Rows) < 100 {
					break
				}
				if page == 200 {
					return errors.New("DNS取消清理查询超过分页上限")
				}
			}
			if found > 1 {
				return errors.New("DNS取消清理找到多个相同记录，请先核对外部平台")
			}
		}
		if record.ID != "" {
			if record.Name != planned.Name || !strings.EqualFold(record.Type, planned.Type) || record.Value != planned.Value || len(record.Values) > 1 {
				return errors.New("DNS验证记录已经变化，取消未删除其他解析")
			}
			if err = c.runner.check(ctx, c.job); err != nil {
				return err
			}
			if err = provider.DeleteRecord(ctx, record.ID); err != nil && !errors.Is(err, dns.ErrNotFound) {
				return err
			}
		}
		if _, err = c.runner.Store.DB.ExecContext(ctx, "UPDATE dns_challenge_intents SET state='cleaned',updated_at=UTC_TIMESTAMP(6) WHERE job_id=? AND challenge_key=?", item.job, item.key); err != nil {
			return err
		}
	}
	return nil
}

func certificateCheckpointHasOrder(provider string, checkpoint certprovider.Checkpoint) bool {
	if checkpoint.OrderURL != "" {
		return true
	}
	key := map[string]string{"tencent": "CertificateId", "aliyun": "InstanceId", "ucloud": "CertificateID", "huoshan": "instance_id"}[provider]
	raw, _ := json.Marshal(checkpoint.Metadata[key])
	return key != "" && string(raw) != "null" && string(raw) != `""`
}
