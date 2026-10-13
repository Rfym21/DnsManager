package automation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (r *Runner) optimizationQuota(ctx context.Context, d OptimizationData) (any, error) {
	client, err := r.Store.HTTPClient(ctx, d.SourceConfig, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return fetchOptimizationQuota(ctx, client, d)
}

func fetchOptimizationQuota(ctx context.Context, client *http.Client, d OptimizationData) (map[string]any, error) {
	if d.SourceProvider == "xingpingcn" {
		return map[string]any{"source_provider": d.SourceProvider, "unlimited": true}, nil
	}
	base := strings.TrimSuffix(d.SourceConfig["api_base"], "/")
	switch d.SourceProvider {
	case "wetest":
		if base == "" {
			base = "https://www.wetest.vip/api/cf2dns"
		}
	case "hostmonit":
		if base == "" {
			base = "https://api.hostmonit.com"
		}
	default:
		return nil, errors.New("该来源不提供配额查询")
	}
	if d.SourceConfig["key"] == "" {
		return nil, errors.New("配额查询需要来源密钥")
	}
	u, err := url.Parse(base + "/get_license")
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("优选IP来源URL无效")
	}
	q := u.Query()
	q.Set("license", d.SourceConfig["key"])
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("配额请求无效")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("配额来源连接失败")
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return nil, errors.New("配额来源拒绝请求")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("配额响应超过限制")
	}
	var data struct {
		Code  int             `json:"code"`
		Count json.RawMessage `json:"count"`
	}
	if json.Unmarshal(raw, &data) != nil || data.Code != 200 {
		return nil, errors.New("获取剩余请求次数失败")
	}
	var count json.Number
	if json.Unmarshal(data.Count, &count) != nil {
		return nil, errors.New("配额响应缺少剩余次数")
	}
	n, err := count.Int64()
	if err != nil || n < 0 {
		return nil, errors.New("配额响应剩余次数无效")
	}
	return map[string]any{"source_provider": d.SourceProvider, "unlimited": false, "remaining": n}, nil
}
