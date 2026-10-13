package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type cfDNSReceipt struct {
	Zone     string `json:"zone"`
	Hostname string `json:"hostname"`
	ID       string `json:"id,omitempty"`
	Token    string `json:"token"`
	Created  bool   `json:"created"`
}
type cfTunnelJournal struct {
	Stage    string         `json:"stage"`
	Previous map[string]any `json:"previous,omitempty"`
	Desired  map[string]any `json:"desired,omitempty"`
	Receipts []cfDNSReceipt `json:"receipts,omitempty"`
	Pending  []cfDNSReceipt `json:"pending,omitempty"`
}

func cfTunnelPath(c cfClient, tunnel string) string {
	return "/accounts/" + url.PathEscape(c.accountID) + "/cfd_tunnel/" + url.PathEscape(tunnel)
}
func cfDeleteTunnel(r *http.Request, c cfClient, tunnel string) (json.RawMessage, error) {
	result, err := c.call(r, http.MethodDelete, cfTunnelPath(c, tunnel), nil)
	var remote *cfError
	if errors.As(err, &remote) && remote.Status == http.StatusNotFound {
		// A previous delete may have succeeded before its owned-DNS cleanup.
		return json.RawMessage(`{"id":""}`), nil
	}
	return result, err
}
func cfIngressHosts(config map[string]any) map[string]bool {
	hosts := map[string]bool{}
	for _, raw := range cfArray(config["ingress"]) {
		name := cfString(cfObject(raw)["hostname"])
		if name != "" {
			hosts[name] = true
		}
	}
	return hosts
}
func cfDNSList(r *http.Request, c cfClient, zone, name string) ([]map[string]any, error) {
	return c.list(r, "/zones/"+url.PathEscape(zone)+"/dns_records", url.Values{"name": {name}})
}
func cfFindDNS(r *http.Request, c cfClient, receipt cfDNSReceipt, tunnel string) (map[string]any, error) {
	rows, err := cfDNSList(r, c, receipt.Zone, receipt.Hostname)
	if err != nil {
		return nil, err
	}
	for _, record := range rows {
		if cfString(record["name"]) == receipt.Hostname && cfString(record["type"]) == "CNAME" && strings.TrimSuffix(cfString(record["content"]), ".") == tunnel+".cfargotunnel.com" && cfString(record["comment"]) == "dnsmgr:"+receipt.Token && (receipt.ID == "" || cfString(record["id"]) == receipt.ID) {
			return record, nil
		}
	}
	return nil, nil
}
func cfCreateOwnedDNS(r *http.Request, c cfClient, receipt *cfDNSReceipt, tunnel string) error {
	existing, err := cfFindDNS(r, c, *receipt, tunnel)
	if err != nil {
		return err
	}
	if existing != nil {
		receipt.ID = cfString(existing["id"])
		receipt.Created = true
		return nil
	}
	rows, err := cfDNSList(r, c, receipt.Zone, receipt.Hostname)
	if err != nil {
		return err
	}
	for _, record := range rows {
		if cfString(record["name"]) != receipt.Hostname {
			continue
		}
		if cfString(record["type"]) == "CNAME" && strings.TrimSuffix(cfString(record["content"]), ".") == tunnel+".cfargotunnel.com" && record["proxied"] == true {
			return nil
		}
		return errors.New("主机名已有其他DNS记录，未覆盖现有解析")
	}
	raw, err := c.call(r, http.MethodPost, "/zones/"+url.PathEscape(receipt.Zone)+"/dns_records", map[string]any{"type": "CNAME", "name": receipt.Hostname, "content": tunnel + ".cfargotunnel.com", "proxied": true, "ttl": 1, "comment": "dnsmgr:" + receipt.Token})
	if err != nil {
		return err
	}
	value, err := cfParseMap(raw)
	if err != nil {
		return err
	}
	receipt.ID = cfString(value["id"])
	receipt.Created = true
	if receipt.ID == "" {
		return errors.New("Cloudflare未返回新DNS记录ID")
	}
	return nil
}
func cfCleanupOwnedDNS(r *http.Request, c cfClient, receipt cfDNSReceipt, tunnel string) error {
	record, err := cfFindDNS(r, c, receipt, tunnel)
	if err != nil {
		return err
	}
	if record == nil {
		return nil
	}
	_, err = c.call(r, http.MethodDelete, "/zones/"+url.PathEscape(receipt.Zone)+"/dns_records/"+url.PathEscape(cfString(record["id"])), nil)
	var remote *cfError
	if errors.As(err, &remote) && remote.Status == http.StatusNotFound {
		return nil
	}
	return err
}
func cfApplyIngress(r *http.Request, c cfClient, tunnel string, next map[string]any, version string, sync bool, domains []store.Domain, account string, journal cfTunnelJournal, save func(cfTunnelJournal) error) (map[string]any, error) {
	path := cfTunnelPath(c, tunnel) + "/configurations"
	read := func() (map[string]any, error) {
		raw, err := c.call(r, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		return cfConfig(raw)
	}
	current, err := read()
	if err != nil {
		return nil, err
	}
	// Recover interrupted writes before accepting a new configuration.
	if journal.Stage != "" && journal.Stage != "complete" {
		if cfHash(current) == cfHash(journal.Desired) {
			return cfContinueIngress(r, c, tunnel, current, journal, save)
		}
		if cfHash(current) != cfHash(journal.Previous) {
			return nil, errors.New("Tunnel配置已由其他客户端修改，请先检查未完成的DNS同步")
		}
		for _, receipt := range journal.Pending {
			if err = cfCleanupOwnedDNS(r, c, receipt, tunnel); err != nil {
				return nil, err
			}
		}
		journal.Pending = nil
		journal.Stage = "complete"
		if err = save(journal); err != nil {
			return nil, err
		}
	}
	if version != "" && version != cfHash(current) {
		return nil, errors.New("Tunnel配置已变化，请刷新后重新保存")
	}
	// Preserve existing non-ingress configuration, including warp-routing and originRequest.
	desired := map[string]any{}
	for key, value := range current {
		desired[key] = value
	}
	for key, value := range next {
		desired[key] = value
	}
	if err = cfValidateIngress(desired); err != nil {
		return nil, err
	}
	pending := []cfDNSReceipt{}
	if sync {
		existing := map[string]bool{}
		for _, receipt := range journal.Receipts {
			existing[receipt.Hostname] = true
		}
		for hostname := range cfIngressHosts(desired) {
			domain, e := cfBestDomain(domains, hostname, account)
			if e != nil {
				return nil, e
			}
			rows, e := cfDNSList(r, c, domain.ProviderDomainID, hostname)
			if e != nil {
				return nil, e
			}
			for _, record := range rows {
				if cfString(record["name"]) != hostname {
					continue
				}
				if cfString(record["type"]) != "CNAME" || strings.TrimSuffix(cfString(record["content"]), ".") != tunnel+".cfargotunnel.com" || record["proxied"] != true {
					return nil, errors.New("Tunnel主机名已有其他DNS解析，请先确认并处理冲突")
				}
			}
			if existing[hostname] {
				continue
			}
			token, e := store.ID()
			if e != nil {
				return nil, e
			}
			pending = append(pending, cfDNSReceipt{Zone: domain.ProviderDomainID, Hostname: hostname, Token: token})
		}
	}
	journal.Previous = current
	journal.Desired = desired
	journal.Pending = pending
	journal.Stage = "config_pending"
	if err = save(journal); err != nil {
		return nil, err
	}
	if _, err = c.call(r, http.MethodPut, path, map[string]any{"config": desired}); err != nil {
		return nil, err
	}
	journal.Stage = "dns_pending"
	if err = save(journal); err != nil {
		return nil, err
	}
	return cfContinueIngress(r, c, tunnel, desired, journal, save)
}
func cfContinueIngress(r *http.Request, c cfClient, tunnel string, current map[string]any, journal cfTunnelJournal, save func(cfTunnelJournal) error) (map[string]any, error) {
	if journal.Stage == "rollback_pending" {
		return nil, cfRollbackIngress(r, c, tunnel, journal, save, errors.New("恢复上一轮DNS同步失败"))
	}
	for index := range journal.Pending {
		if err := cfCreateOwnedDNS(r, c, &journal.Pending[index], tunnel); err != nil {
			return nil, cfRollbackIngress(r, c, tunnel, journal, save, err)
		}
		if err := save(journal); err != nil {
			return nil, err
		}
	}
	// Clean only records bearing this operation's random ownership token and exact target.
	wanted := cfIngressHosts(journal.Desired)
	kept := []cfDNSReceipt{}
	for _, receipt := range journal.Receipts {
		if wanted[receipt.Hostname] {
			kept = append(kept, receipt)
		} else {
			if err := cfCleanupOwnedDNS(r, c, receipt, tunnel); err != nil {
				return nil, err
			}
		}
	}
	for _, receipt := range journal.Pending {
		if receipt.Created {
			kept = append(kept, receipt)
		}
	}
	journal.Receipts = kept
	journal.Pending = nil
	journal.Stage = "complete"
	journal.Previous = nil
	journal.Desired = nil
	if err := save(journal); err != nil {
		return nil, err
	}
	return map[string]any{"config": current, "version": cfHash(current), "dns_synced": true}, nil
}
func cfRollbackIngress(r *http.Request, c cfClient, tunnel string, journal cfTunnelJournal, save func(cfTunnelJournal) error, cause error) error {
	journal.Stage = "rollback_pending"
	if err := save(journal); err != nil {
		return fmt.Errorf("DNS同步失败且回滚状态未保存: %w", err)
	}
	path := cfTunnelPath(c, tunnel) + "/configurations"
	raw, err := c.call(r, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	current, err := cfConfig(raw)
	if err != nil {
		return err
	}
	if cfHash(current) != cfHash(journal.Desired) && cfHash(current) != cfHash(journal.Previous) {
		return errors.New("DNS同步失败，当前Tunnel配置已变化；回滚需要人工确认")
	}
	if cfHash(current) == cfHash(journal.Desired) {
		if _, err = c.call(r, http.MethodPut, path, map[string]any{"config": journal.Previous}); err != nil {
			return fmt.Errorf("DNS同步失败且Tunnel回滚未完成: %w", err)
		}
	}
	for _, receipt := range journal.Pending {
		if err = cfCleanupOwnedDNS(r, c, receipt, tunnel); err != nil {
			return fmt.Errorf("Tunnel已回滚，DNS清理需重试: %w", err)
		}
	}
	journal.Pending = nil
	journal.Stage = "complete"
	journal.Desired = nil
	journal.Previous = nil
	if err = save(journal); err != nil {
		return err
	}
	return fmt.Errorf("Tunnel配置已回滚: %w", cause)
}
