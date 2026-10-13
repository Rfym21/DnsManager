package automation

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/dns-manager/dnsmgr/server/internal/transport"
	"net/http"
	"net/url"
	"time"
)

func (r *Runner) testProxy(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d struct {
		URL    string `json:"url"`
		Target string `json:"test_url"`
	}
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	if d.Target == "" {
		d.Target = "https://example.com"
	}
	u, err := url.Parse(d.Target)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("代理测试需要有效 HTTP(S) 目标")
	}
	client, err := transport.Client(d.URL, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if err = r.check(ctx, j); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "HEAD", d.Target, nil)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("代理测试连接失败")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		return nil, errors.New("代理目标返回错误状态")
	}
	return map[string]any{"connected": true, "latency_ms": time.Since(started).Milliseconds(), "status": res.StatusCode}, nil
}
