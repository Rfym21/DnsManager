package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/net/idna"
)

func cfString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}
func cfObject(v any) map[string]any { object, _ := v.(map[string]any); return object }
func cfArray(v any) []any           { array, _ := v.([]any); return array }
func cfHash(v any) string {
	raw, _ := json.Marshal(v)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func cfNormalizeHostname(raw string, record bool) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if name == "" || net.ParseIP(name) != nil || strings.ContainsAny(name, "/:?@#\\") {
		return "", errors.New("主机名须为有效域名，不能包含协议、IP或端口")
	}
	labelsToConvert := strings.Split(name, ".")
	for i, label := range labelsToConvert {
		if record && strings.HasPrefix(label, "_") {
			continue
		}
		converted, e := idna.Lookup.ToASCII(label)
		if e != nil {
			return "", errors.New("域名格式不正确")
		}
		labelsToConvert[i] = converted
	}
	ascii := strings.Join(labelsToConvert, ".")
	if len(ascii) > 253 {
		return "", errors.New("域名格式不正确")
	}
	labelPattern := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	if record {
		labelPattern = regexp.MustCompile(`^[_a-z0-9](?:[_a-z0-9-]*[_a-z0-9])?$`)
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", errors.New("域名须包含完整后缀")
	}
	for _, label := range labels {
		if len(label) > 63 || !labelPattern.MatchString(label) {
			return "", errors.New("域名标签格式不正确")
		}
	}
	return ascii, nil
}
func cfValidateSSL(ssl map[string]any) error {
	if method, ok := ssl["method"]; ok && method != "txt" && method != "http" && method != "email" {
		return errors.New("证书验证方式须为TXT、HTTP或Email")
	}
	if settings := cfObject(ssl["settings"]); settings != nil {
		if tls, exists := settings["min_tls_version"]; exists && tls != "1.0" && tls != "1.1" && tls != "1.2" && tls != "1.3" {
			return errors.New("最低TLS版本无效")
		}
	}
	return nil
}
func cfConfig(raw json.RawMessage) (map[string]any, error) {
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		return nil, errors.New("Tunnel配置格式不正确")
	}
	if config := cfObject(result["config"]); config != nil {
		return config, nil
	}
	return result, nil
}
func cfValidateIngress(config map[string]any) error {
	rows := cfArray(config["ingress"])
	if len(rows) == 0 || len(rows) > 1000 {
		return errors.New("需要入口规则与最后的回退规则，最多1000条")
	}
	seen := map[string]bool{}
	for index, raw := range rows {
		row := cfObject(raw)
		if row == nil {
			return errors.New("入口规则格式不正确")
		}
		hostname := cfString(row["hostname"])
		service := cfString(row["service"])
		if strings.TrimSpace(service) == "" {
			return errors.New("入口服务不能为空")
		}
		if hostname == "" {
			if index != len(rows)-1 {
				return errors.New("未指定主机名的回退规则必须位于最后")
			}
			continue
		}
		name, err := cfNormalizeHostname(hostname, false)
		if err != nil {
			return err
		}
		row["hostname"] = name
		if index == len(rows)-1 {
			return errors.New("最后一条必须是不指定主机名的回退规则")
		}
		identity := name + "\x00" + cfString(row["path"])
		if seen[identity] {
			return errors.New("入口主机名与路径重复")
		}
		seen[identity] = true
	}
	return nil
}
func cfMatchingDomains(domains []store.Domain, hostname, account string) []store.Domain {
	items := []store.Domain{}
	best := 0
	for _, domain := range domains {
		if account != "" && (domain.AccountID != account || domain.Provider != "cloudflare") {
			continue
		}
		name := strings.ToLower(domain.ASCIIName)
		if name == "" {
			name = strings.ToLower(domain.Name)
		}
		if hostname != "" {
			target := strings.TrimSuffix(strings.ToLower(hostname), ".")
			if target != name && !strings.HasSuffix(target, "."+name) {
				continue
			}
			if len(name) > best {
				items = nil
				best = len(name)
			}
			if len(name) < best {
				continue
			}
		}
		items = append(items, domain)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}
func cfBestDomain(domains []store.Domain, hostname, account string) (store.Domain, error) {
	items := cfMatchingDomains(domains, hostname, account)
	if len(items) != 1 {
		return store.Domain{}, errors.New("主机名须唯一匹配当前账户中已导入的Cloudflare域名")
	}
	return items[0], nil
}
func cfRecordName(domain store.Domain, hostname string) (string, error) {
	name := domain.ASCIIName
	if name == "" {
		name = domain.Name
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if hostname == name {
		return "@", nil
	}
	if strings.HasSuffix(hostname, "."+name) {
		return strings.TrimSuffix(hostname, "."+name), nil
	}
	return "", errors.New("验证记录不属于目标域名")
}
func (a *API) cfAudit(r *http.Request, action, resource, domain string, detail any) error {
	return a.Store.Audit(r.Context(), principal(r).User.ID, "cloudflare."+action, "cloudflare", resource, domain, middleware.GetReqID(r.Context()), detail)
}
func cfMergeSSL(current, update map[string]any) map[string]any {
	result := map[string]any{}
	for _, key := range []string{"method", "type", "settings"} {
		if value, ok := current[key]; ok {
			result[key] = value
		}
	}
	if result["method"] == nil {
		result["method"] = "txt"
	}
	if result["type"] == nil {
		result["type"] = "dv"
	}
	for key, value := range update {
		if key == "settings" {
			settings := map[string]any{}
			for k, v := range cfObject(result[key]) {
				settings[k] = v
			}
			for k, v := range cfObject(value) {
				settings[k] = v
			}
			result[key] = settings
		} else {
			result[key] = value
		}
	}
	return result
}
func cfParseMap(raw json.RawMessage) (map[string]any, error) {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || value == nil {
		return nil, fmt.Errorf("Cloudflare对象格式不正确")
	}
	return value, nil
}
