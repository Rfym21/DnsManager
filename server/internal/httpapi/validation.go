package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/automation"
	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/redaction"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func validateObject(o store.Object) error {
	switch o.Kind {
	case "issuer_accounts", "deploy_accounts":
		var d struct {
			Provider string            `json:"provider"`
			Config   map[string]string `json:"config"`
		}
		if json.Unmarshal(o.Data, &d) != nil || d.Provider == "" {
			return errors.New("需要选择供应商并填写账户配置")
		}
	case "certificates":
		var d automation.CertificateData
		if json.Unmarshal(o.Data, &d) != nil {
			return errors.New("证书配置格式不正确")
		}
		if len(d.Domains) == 0 || len(d.Domains) > 100 {
			return errors.New("证书需要1–100个域名")
		}
		if d.AccountID != "" && d.KeyType != "rsa" && d.KeyType != "ecdsa" && d.KeyType != "ec" {
			return errors.New("密钥类型必须是RSA或ECDSA")
		}
		if d.AccountID == "" {
			result, err := certprovider.ParseResult(d.Fullchain, d.PrivateKey)
			if err != nil {
				return errors.New("手动导入需要有效且匹配的PEM证书和私钥")
			}
			d.Status = "issued"
			d.Fingerprint = result.Fingerprint
			d.NotBefore = result.NotBefore
			d.NotAfter = result.NotAfter
			d.Issuer = result.Issuer
			d.AutoRenew = false
			o.Data, _ = json.Marshal(d)
		}
	case "deployments":
		var d automation.DeploymentData
		if json.Unmarshal(o.Data, &d) != nil || d.AccountID == "" || d.CertificateID == "" {
			return errors.New("部署需要目标账户和已签发证书")
		}
		if err := automation.ValidateDeploymentWindow(d.Window); err != nil {
			return err
		}
		if _, err := automation.NormalizeDeploymentRetryPolicy(d.RetryPolicy); err != nil {
			return err
		}
	case "monitors":
		var d automation.MonitorData
		if json.Unmarshal(o.Data, &d) != nil || d.RecordID == "" {
			return errors.New("监控需要绑定解析记录")
		}
		if d.Mode != "notify" && d.Mode != "disable" && d.Mode != "switch" && d.Mode != "conditional" {
			return errors.New("容灾策略类型不正确")
		}
		if d.Mode == "switch" && (d.MainValue == "" || d.BackupValue == "" || d.MainValue == d.BackupValue) {
			return errors.New("主备值不能为空或相同")
		}
		if d.Mode != "conditional" && (d.Target == "" || (d.Protocol != "icmp" && d.Protocol != "tcp" && d.Protocol != "http")) {
			return errors.New("检测目标或协议不正确")
		}
		if d.Mode == "conditional" && (len(d.ConditionIDs) == 0 || d.ConditionThreshold < 0 || d.ConditionThreshold >= len(d.ConditionIDs)) {
			return errors.New("条件监控需要关联监控，健康数量阈值须在0与关联数量减1之间")
		}
		if d.FrequencySeconds < 5 || d.TimeoutSeconds < 1 || d.TimeoutSeconds > d.FrequencySeconds {
			return errors.New("检测间隔至少5秒，超时必须在间隔内")
		}
	case "schedules":
		var d automation.ScheduleData
		if json.Unmarshal(o.Data, &d) != nil || d.RecordID == "" {
			return errors.New("调度需要绑定记录")
		}
		switch d.Operation {
		case "update", "enable", "disable", "delete":
		default:
			return errors.New("调度操作不正确")
		}
		if _, err := d.Schedule.Preview(time.Now().UTC(), 5); err != nil {
			return fmt.Errorf("调度规则：%w", err)
		}
	case "optimizations":
		var d automation.OptimizationData
		if json.Unmarshal(o.Data, &d) != nil || len(d.RecordNames) == 0 || d.RecordCount < 1 || d.RecordCount > 50 {
			return errors.New("优选策略需要IP来源、记录名称及1–50条记录")
		}
		if len(d.RecordNames) > 50 {
			return errors.New("优选策略最多50个记录名称")
		}
		seen := map[string]bool{}
		for _, name := range d.RecordNames {
			if seen[name] {
				return errors.New("优选记录名称不能重复")
			}
			seen[name] = true
			if err := dns.ValidateRecord(dns.Record{Name: name, Type: "A", Value: "192.0.2.1", TTL: 1}, "example.invalid"); err != nil {
				return errors.New("优选记录名称无效")
			}
		}
		families := d.IPTypes
		if len(families) == 0 {
			families = []string{d.IPType}
		}
		if len(families) > 2 || (len(families) == 2 && families[0] == families[1]) {
			return errors.New("IP类型不能重复")
		}
		for _, family := range families {
			if family != "ipv4" && family != "ipv6" {
				return errors.New("IP类型不正确")
			}
			if d.SourceProvider == "xingpingcn" && family != "ipv4" {
				return errors.New("xingpingcn仅支持IPv4")
			}
		}
		if d.LineMode != "" && d.LineMode != "telecom_default" {
			return errors.New("默认线路模式不正确")
		}
		switch d.SourceProvider {
		case "", "custom":
			if d.SourceURL == "" || (d.IPType != "ipv4" && d.IPType != "ipv6") {
				return errors.New("自定义来源需要URL和IP类型")
			}
		case "wetest":
			if d.SourceConfig["key"] == "" || !strings.Contains("1234", d.SourceConfig["cdn_type"]) || len(d.SourceConfig["cdn_type"]) != 1 {
				return errors.New("Wetest需要密钥和有效CDN类型")
			}
		case "hostmonit":
			if d.SourceConfig["key"] == "" {
				return errors.New("Hostmonit需要API密钥")
			}
		case "xingpingcn":
		default:
			return errors.New("优选来源不正确")
		}
	case "delegations":
		var d struct {
			Domain string `json:"domain"`
			Target string `json:"target"`
		}
		if json.Unmarshal(o.Data, &d) != nil || d.Domain == "" || d.Target == "" {
			return errors.New("委托需要域名和验证目标")
		}
	case "notification_channels":
		var d struct {
			Provider string            `json:"provider"`
			Config   map[string]string `json:"config"`
		}
		if json.Unmarshal(o.Data, &d) != nil || d.Provider == "" {
			return errors.New("通知渠道类型不正确")
		}
	}
	if (o.Kind == "monitors" || o.Kind == "schedules" || o.Kind == "optimizations") && o.DomainID == "" {
		return errors.New("自动化需要选择授权域名")
	}
	return nil
}
func effectiveSecretKey(key string) bool {
	return redaction.Key(key)
}
