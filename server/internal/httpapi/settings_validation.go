package httpapi

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/transport"
)

func validateSetting(name string, raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("设置必须为 JSON 对象")
	}
	switch name {
	case "site":
		if v, ok := fields["certificate_renew_before_days"]; ok {
			var n int
			if json.Unmarshal(v, &n) != nil || n < 1 || n > 365 {
				return errors.New("证书提醒天数须在1–365之间")
			}
		}
		if v, ok := fields["timezone"]; ok {
			var zone string
			if json.Unmarshal(v, &zone) != nil {
				return errors.New("时区不正确")
			}
			if _, e := time.LoadLocation(zone); e != nil {
				return errors.New("请填写有效 IANA 时区")
			}
		}
		if v, ok := fields["domain_expiry_days"]; ok {
			var days string
			if json.Unmarshal(v, &days) != nil {
				return errors.New("到期提醒天数不正确")
			}
			for _, d := range strings.Split(days, ",") {
				if strings.TrimSpace(d) == "" {
					continue
				}
				n, e := strconv.Atoi(strings.TrimSpace(d))
				if e != nil || n < 0 || n > 365 {
					return errors.New("到期提醒天数须在0–365之间")
				}
			}
		}
	case "network":
		if v, ok := fields["proxy_url"]; ok {
			var value string
			if json.Unmarshal(v, &value) != nil {
				return errors.New("代理地址不正确")
			}
			if value != "" {
				if _, err := transport.Client(value, time.Second); err != nil {
					return err
				}
			}
		}
	case "security":
		if v, ok := fields["login_captcha"]; ok {
			var enabled bool
			if json.Unmarshal(v, &enabled) != nil {
				return errors.New("验证码开关不正确")
			}
		}
	case "retention":
		for _, k := range []string{"audit_days", "job_days"} {
			if v, ok := fields[k]; ok {
				var n int
				if json.Unmarshal(v, &n) != nil || n < 7 || n > 3650 {
					return errors.New("日志保留天数须在7–3650之间")
				}
			}
		}
	}
	return nil
}
