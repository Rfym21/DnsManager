package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/go-chi/chi/v5"
	mdns "github.com/miekg/dns"
)

type recordDNSAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}
type recordCheckResult struct {
	Record    dns.Record        `json:"record"`
	QueryName string            `json:"queryName"`
	Answers   []recordDNSAnswer `json:"answers"`
	Matched   bool              `json:"matched"`
	Status    string            `json:"status"`
	RCode     int               `json:"rcode"`
}

func (a *API) recordDetail(w http.ResponseWriter, r *http.Request) {
	_, provider, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	record, err := provider.GetRecord(r.Context(), chi.URLParam(r, "record"))
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	record.Version = recordVersion(record)
	send(w, http.StatusOK, map[string]any{"record": record})
}
func (a *API) recordCheck(w http.ResponseWriter, r *http.Request) {
	domain, provider, ok := a.domainProvider(w, r, "dns:read")
	if !ok {
		return
	}
	record, err := provider.GetRecord(r.Context(), chi.URLParam(r, "record"))
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	record.Version = recordVersion(record)
	name := record.Name
	zone := domain.ASCIIName
	if zone == "" {
		zone = domain.Name
	}
	if name == "@" || name == "" {
		name = zone
	} else if !strings.EqualFold(strings.TrimSuffix(name, "."), zone) && !strings.HasSuffix(strings.ToLower(strings.TrimSuffix(name, ".")), "."+strings.ToLower(zone)) {
		name = name + "." + zone
	}
	queryName, err := cfNormalizeHostname(strings.ReplaceAll(name, "*.", "wildcard."), true)
	if err != nil {
		a.fail(w, r, 422, "invalid_query_name", "平台记录名称不适合DNS检测")
		return
	}
	if strings.HasPrefix(name, "*.") {
		queryName = "*." + strings.TrimPrefix(queryName, "wildcard.")
	}
	kind, ok := mdns.StringToType[strings.ToUpper(record.Type)]
	if !ok || kind == mdns.TypeANY || kind == mdns.TypeAXFR || kind == mdns.TypeIXFR || kind == mdns.TypeOPT {
		a.fail(w, r, 422, "unsupported_record_type", "该记录类型不支持公开DNS检测")
		return
	}
	result, err := a.checkRecordDNS(r, record, queryName, kind)
	if err != nil {
		a.fail(w, r, 502, "dns_check_failed", err.Error())
		return
	}
	send(w, http.StatusOK, result)
}
func (a *API) checkRecordDNS(r *http.Request, record dns.Record, name string, kind uint16) (recordCheckResult, error) {
	result := recordCheckResult{Record: record, QueryName: name, Answers: []recordDNSAnswer{}, Status: "not_found"}
	message := new(mdns.Msg)
	message.SetQuestion(mdns.Fqdn(name), kind)
	raw, err := message.Pack()
	if err != nil {
		return result, errors.New("DNS查询无法编码")
	}
	endpoint := a.DoHEndpoint
	if endpoint == "" {
		endpoint = "https://dns.google/dns-query"
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Fragment != "" {
		return result, errors.New("DoH服务配置无效")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return result, errors.New("DNS查询请求无效")
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := a.DoHClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, err := client.Do(req)
	if err != nil {
		return result, errors.New("公开DNS查询连接失败")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, errors.New("公开DNS服务未接受查询")
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return result, errors.New("公开DNS响应无法完整读取")
	}
	answer := new(mdns.Msg)
	if answer.Unpack(raw) != nil || !answer.Response || answer.Id != message.Id || len(answer.Question) != 1 || !strings.EqualFold(answer.Question[0].Name, message.Question[0].Name) || answer.Question[0].Qtype != kind {
		return result, errors.New("公开DNS响应与请求不匹配")
	}
	result.RCode = answer.Rcode
	if answer.Rcode != mdns.RcodeSuccess && answer.Rcode != mdns.RcodeNameError {
		result.Status = "resolver_error"
		return result, nil
	}
	values := []string{}
	for _, rr := range answer.Answer {
		value := recordRRValue(rr)
		result.Answers = append(result.Answers, recordDNSAnswer{Name: strings.TrimSuffix(rr.Header().Name, "."), Type: mdns.TypeToString[rr.Header().Rrtype], TTL: rr.Header().Ttl, Value: value})
		if rr.Header().Rrtype == kind && strings.EqualFold(strings.TrimSuffix(rr.Header().Name, "."), name) {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return result, nil
	}
	result.Matched = recordValuesMatch(record, values)
	result.Status = "mismatch"
	if result.Matched {
		result.Status = "active"
	}
	return result, nil
}
func recordRRValue(rr mdns.RR) string {
	switch v := rr.(type) {
	case *mdns.A:
		return v.A.String()
	case *mdns.AAAA:
		return v.AAAA.String()
	case *mdns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *mdns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *mdns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	case *mdns.MX:
		return strconv.Itoa(int(v.Preference)) + " " + strings.TrimSuffix(v.Mx, ".")
	case *mdns.TXT:
		return strings.Join(v.Txt, "")
	default:
		parts := strings.SplitN(rr.String(), "\t", 5)
		if len(parts) == 5 {
			return parts[4]
		}
		return rr.String()
	}
}
func recordValuesMatch(record dns.Record, actual []string) bool {
	expected := record.Values
	if len(expected) == 0 {
		expected = []string{record.Value}
	}
	for _, wanted := range expected {
		matched := false
		if record.Type == "MX" && record.Priority != nil {
			wanted = strconv.Itoa(*record.Priority) + " " + wanted
		}
		for _, value := range actual {
			if strings.EqualFold(record.Type, "MX") && record.Priority == nil {
				parts := strings.Fields(value)
				if len(parts) == 2 {
					value = parts[1]
				}
			}
			switch strings.ToUpper(record.Type) {
			case "A", "AAAA":
				left, right := net.ParseIP(wanted), net.ParseIP(value)
				matched = left != nil && right != nil && left.Equal(right)
			case "TXT":
				matched = wanted == value
			default:
				matched = strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(wanted), "."), strings.TrimSuffix(strings.TrimSpace(value), "."))
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	return len(expected) > 0
}
