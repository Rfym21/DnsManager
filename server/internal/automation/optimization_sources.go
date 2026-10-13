package automation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var optimizationLines = map[string]map[string]string{
	"aliyun": {"DEF": "default", "CT": "telecom", "CU": "unicom", "CM": "mobile", "AB": "oversea"}, "dnspod": {"DEF": "0", "CT": "10=0", "CU": "10=1", "CM": "10=3", "AB": "3=0"}, "huawei": {"DEF": "default_view", "CT": "Dianxin", "CU": "Liantong", "CM": "Yidong", "AB": "Abroad"}, "west": {"DEF": "", "CT": "LTEL", "CU": "LCNC", "CM": "LMOB", "AB": "LFOR"}, "dnsla": {"DEF": "", "CT": "84613316902921216", "CU": "84613316923892736", "CM": "84613316953252864"}, "huoshan": {"DEF": "default", "CT": "telecom", "CU": "unicom", "CM": "mobile", "AB": "oversea"}, "baidu": {"DEF": "default", "CT": "ct", "CU": "cnc", "CM": "cmnet"}, "jdcloud": {"DEF": "-1", "CT": "1", "CU": "2", "CM": "3", "AB": "4"}, "bt": {"DEF": "0", "CT": "285344768", "CU": "285345792", "CM": "285346816"}, "qingcloud": {"DEF": "0", "CT": "2", "CU": "3", "CM": "4", "AB": "8"}, "cloudflare": {"DEF": "0"}, "aws": {"DEF": "default"}, "namesilo": {"DEF": "default"}, "henet": {"DEF": "default"}, "powerdns": {"DEF": "default"}, "spaceship": {"DEF": "default"}, "aliyunesa": {"DEF": "0"}, "tencenteo": {"DEF": "Default"}, "dnsmgr": {"DEF": "default"}, "goedge": {"DEF": "default"},
}

func fetchOptimizationSource(ctx context.Context, client *http.Client, d OptimizationData, family string) (map[string][]string, error) {
	base := strings.TrimSuffix(d.SourceConfig["api_base"], "/")
	method := "POST"
	path := ""
	var body io.Reader
	switch d.SourceProvider {
	case "wetest":
		if base == "" {
			base = "https://www.wetest.vip/api/cf2dns"
		}
		path = map[string]string{"1": "/get_cloudflare_ip", "2": "/get_cloudfront_ip", "3": "/get_gcore_ip", "4": "/get_edgeone_ip"}[d.SourceConfig["cdn_type"]]
		if path == "" {
			return nil, errors.New("不支持的CDN类型")
		}
	case "hostmonit":
		if base == "" {
			base = "https://api.hostmonit.com"
		}
		path = "/get_optimization_ip"
	case "xingpingcn":
		if family != "ipv4" {
			return nil, errors.New("xingpingcn优选来源仅支持IPv4")
		}
		method = "GET"
		if d.SourceURL != "" {
			base = d.SourceURL
		} else {
			base = "https://raw.githubusercontent.com/xingpingcn/enhanced-FaaS-in-China/refs/heads/main/Cf.json"
		}
	default:
		return nil, errors.New("未知优选IP来源")
	}
	if method == "POST" {
		if d.SourceConfig["key"] == "" {
			return nil, errors.New("优选IP来源需要API密钥")
		}
		raw, _ := json.Marshal(map[string]string{"key": d.SourceConfig["key"], "type": map[string]string{"ipv4": "v4", "ipv6": "v6"}[family]})
		body = bytes.NewReader(raw)
	}
	u, err := url.Parse(base + path)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("优选IP来源URL无效")
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("优选IP来源连接失败")
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("优选来源返回HTTP%d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, errors.New("优选来源响应超过限制")
	}
	var data map[string]json.RawMessage
	if json.Unmarshal(raw, &data) != nil {
		return nil, errors.New("优选来源响应格式错误")
	}
	grouped := map[string]json.RawMessage{}
	if d.SourceProvider == "xingpingcn" {
		var cf struct {
			Result map[string]json.RawMessage `json:"result"`
		}
		if json.Unmarshal(data["Cf"], &cf) != nil || cf.Result == nil {
			return nil, errors.New("优选来源缺少Cf.result")
		}
		for key, line := range map[string]string{"dianxin": "CT", "liantong": "CU", "yidong": "CM"} {
			grouped[line] = cf.Result[key]
		}
	} else {
		var code int
		json.Unmarshal(data["code"], &code)
		if code != 200 {
			return nil, errors.New("优选IP来源拒绝请求")
		}
		if json.Unmarshal(data["info"], &grouped) != nil {
			return nil, errors.New("优选来源缺少线路数据")
		}
	}
	result := map[string][]string{}
	for _, line := range []string{"DEF", "CT", "CU", "CM", "AB"} {
		if raw := grouped[line]; len(raw) > 0 {
			if ips := parseIPs(raw, family); len(ips) > 0 {
				result[line] = ips
			}
		}
	}
	if len(result) == 0 {
		return nil, errors.New("优选来源没有可用IP")
	}
	return result, nil
}

func (r *Runner) optimizeLegacy(ctx context.Context, j store.Job, o store.Object, d OptimizationData) (any, error) {
	if d.RecordCount < 1 || d.RecordCount > 50 {
		return nil, errors.New("优选记录数量需1–50")
	}
	families := d.IPTypes
	if len(families) == 0 {
		families = []string{d.IPType}
	}
	client, err := r.Store.HTTPClient(ctx, d.SourceConfig, 20*time.Second)
	if err != nil {
		return nil, err
	}
	groups := map[string]map[string][]string{}
	for _, family := range families {
		if family != "ipv4" && family != "ipv6" {
			return nil, errors.New("IP类型不正确")
		}
		groups[family], err = fetchOptimizationSource(ctx, client, d, family)
		if err != nil {
			return nil, err
		}
	}
	var payload struct {
		Action string `json:"action"`
	}
	json.Unmarshal(j.Payload, &payload)
	if payload.Action == "test" {
		return map[string]any{"lines": groups}, nil
	}
	p, err := r.principal(ctx, j)
	if err != nil {
		return nil, err
	}
	zone, provider, err := r.provider(ctx, p, o.DomainID, "dns:write")
	if err != nil {
		return nil, err
	}
	mapping, ok := optimizationLines[provider.Descriptor().ID]
	if !ok {
		return nil, errors.New("该DNS平台不支持线路优选")
	}
	cache := map[string][]dns.Record{}
	plan := optimizationPlan{Fields: map[string]any{"last_run": time.Now().UTC(), "last_lines": groups}, Result: map[string]any{"lines": groups}}
	applicable := 0
	for _, family := range families {
		for _, sourceLine := range []string{"DEF", "CT", "CU", "CM", "AB"} {
			ips := groups[family][sourceLine]
			if len(ips) == 0 {
				continue
			}
			line := sourceLine
			if d.LineMode == "telecom_default" && sourceLine == "CT" && len(groups[family]["DEF"]) == 0 {
				line = "DEF"
			}
			nativeLine, ok := mapping[line]
			if !ok {
				continue
			}
			if len(ips) < d.RecordCount {
				return nil, fmt.Errorf("%s线路有效IP不足", sourceLine)
			}
			ips = ips[:d.RecordCount]
			applicable++
			for _, name := range d.RecordNames {
				mutations, e := planOptimizationIPs(ctx, provider, name, nativeLine, family, ips, max(d.TTL, 1), cache)
				if e != nil {
					return nil, e
				}
				plan.Mutations = append(plan.Mutations, mutations...)
			}
		}
	}
	if applicable == 0 {
		return nil, errors.New("来源返回的线路均不受当前DNS平台支持")
	}
	r.Store.Audit(ctx, j.OwnerID, "optimization.plan", "domain", zone.ID, zone.ID, "", map[string]any{"job_id": j.ID, "operations": len(plan.Mutations)})
	return r.executeOptimizationPlan(ctx, j, o, provider, plan)
}
