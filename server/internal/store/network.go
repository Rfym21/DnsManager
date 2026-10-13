package store

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/transport"
)

func (s *Store) HTTPClient(ctx context.Context, cfg map[string]string, timeout time.Duration) (*http.Client, error) {
	proxyURL := cfg["proxy_url"]
	if proxyURL == "" && (cfg["proxy"] == "1" || cfg["proxy"] == "true") {
		var settings struct {
			URL string `json:"proxy_url"`
		}
		if err := s.Setting(ctx, "network", &settings); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		proxyURL = settings.URL
		if proxyURL == "" {
			return nil, errors.New("账户已启用代理，请先配置网络代理")
		}
	}
	return transport.Client(proxyURL, timeout)
}
