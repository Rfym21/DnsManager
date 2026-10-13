package dns

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type formProvider struct{ *base }

func md5Hex(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
func formMutation(kind, path string, p url.Values) bool {
	switch kind {
	case "namesilo":
		return strings.Contains(path, "AddRecord") || strings.Contains(path, "UpdateRecord") || strings.Contains(path, "DeleteRecord")
	case "west":
		return !strings.HasPrefix(p.Get("act"), "get")
	case "dnsmgr":
		return strings.Contains(path, "/record/") && !strings.Contains(path, "/record/data/")
	}
	return false
}
func (x *formProvider) call(ctx context.Context, path string, p url.Values) (map[string]any, error) {
	if p == nil {
		p = url.Values{}
	}
	method := "POST"
	switch x.kind {
	case "namesilo":
		method = "GET"
		p.Set("version", "1")
		p.Set("type", "json")
		p.Set("key", x.cfg["apikey"])
	case "west":
		stamp := strconv.FormatInt(x.now().UnixMilli(), 10)
		p.Set("username", x.cfg["username"])
		p.Set("time", stamp)
		p.Set("token", md5Hex(x.cfg["username"]+x.cfg["api_password"]+stamp))
	case "dnsmgr":
		stamp := strconv.FormatInt(x.now().Unix(), 10)
		p.Set("uid", x.cfg["uid"])
		p.Set("timestamp", stamp)
		p.Set("sign", md5Hex(x.cfg["uid"]+stamp+x.cfg["key"]))
	}
	q := url.Values{}
	var body []byte
	if method == "GET" {
		q = p
	} else {
		body = []byte(p.Encode())
	}
	raw, status, err := x.raw(ctx, method, path, q, body, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		return nil, classifyProtocolError(err, formMutation(x.kind, path, p))
	}
	var out map[string]any
	if err = decodeJSON(raw, &out); err != nil || out == nil {
		return nil, responseError(x.kind, status, formMutation(x.kind, path, p), "invalid DNS provider JSON response")
	}
	if status >= 400 {
		return nil, &RemoteError{Provider: x.kind, Status: status, Message: firstString(out, "msg", "message", "detail"), UnknownResult: status >= 500 && formMutation(x.kind, path, p)}
	}
	switch x.kind {
	case "namesilo":
		out = obj(out, "reply")
		if _, ok := out["code"]; !ok {
			return nil, responseError(x.kind, status, formMutation(x.kind, path, p), "missing NameSilo result code")
		}
		if integer(out, "code") != 300 {
			return nil, &RemoteError{Provider: x.kind, Status: status, Code: str(out, "code"), Message: str(out, "detail")}
		}
	case "west":
		if _, ok := out["result"]; !ok {
			return nil, responseError(x.kind, status, formMutation(x.kind, path, p), "missing West result code")
		}
		if integer(out, "result") != 200 {
			return nil, &RemoteError{Provider: x.kind, Status: status, Code: str(out, "result"), Message: str(out, "msg")}
		}
		out = obj(out, "data")
	case "dnsmgr":
		if _, ok := out["rows"]; ok {
			return out, nil
		}
		if _, ok := out["code"]; !ok {
			return nil, responseError(x.kind, status, formMutation(x.kind, path, p), "missing DNS Manager result code")
		}
		if integer(out, "code") != 0 {
			return nil, &RemoteError{Provider: x.kind, Status: status, Code: str(out, "code"), Message: str(out, "msg")}
		}
		if data, ok := out["data"].(map[string]any); ok {
			return data, nil
		}
	}
	return out, nil
}
func (x *formProvider) Validate(ctx context.Context) error {
	_, err := x.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (x *formProvider) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	p := url.Values{}
	path := ""
	rowsKey := ""
	totalKey := "total"
	switch x.kind {
	case "namesilo":
		path = "/listDomains"
		p.Set("page", strconv.Itoa(o.Page))
		p.Set("pageSize", strconv.Itoa(o.PageSize))
		rowsKey = "domains"
	case "west":
		path = "/domain/"
		p.Set("act", "getdomains")
		p.Set("page", strconv.Itoa(o.Page))
		p.Set("limit", strconv.Itoa(o.PageSize))
		p.Set("domain", o.Keyword)
		rowsKey = "items"
	case "dnsmgr":
		path = "/api/domain"
		p.Set("offset", strconv.Itoa((o.Page-1)*o.PageSize))
		p.Set("limit", strconv.Itoa(o.PageSize))
		p.Set("kw", o.Keyword)
		rowsKey = "rows"
	}
	out, err := x.call(ctx, path, p)
	if err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	for _, m := range arr(out, rowsKey) {
		name := str(m, "domain")
		id := name
		count := 0
		if x.kind == "dnsmgr" {
			name = str(m, "name")
			id = str(m, "id")
			count = integer(m, "recordcount")
		}
		rows = append(rows, Domain{ID: id, Name: name, RecordCount: count})
	}
	total := integer(out, totalKey)
	if x.kind == "namesilo" {
		total = integer(obj(out, "pager"), "total")
	}
	return DomainPage{Total: total, Rows: rows}, nil
}
func (x *formProvider) normalize(m map[string]any) Record {
	switch x.kind {
	case "namesilo":
		return Record{ID: str(m, "record_id"), Name: relative(str(m, "host"), x.zoneName), Type: str(m, "type"), Value: str(m, "value"), TTL: integer(m, "ttl"), Priority: optionalInt(m, "distance"), Line: "default", Enabled: true}
	case "west":
		return Record{ID: str(m, "id"), Name: str(m, "item"), Type: str(m, "type"), Value: str(m, "value"), TTL: integer(m, "ttl"), Priority: optionalInt(m, "level"), Line: str(m, "line"), Enabled: integer(m, "pause") != 1}
	default:
		return Record{ID: str(m, "RecordId"), Name: str(m, "Name"), Type: str(m, "Type"), Value: str(m, "Value"), TTL: integer(m, "TTL"), Priority: optionalInt(m, "MX"), Weight: optionalInt(m, "Weight"), Remark: str(m, "Remark"), Line: str(m, "Line"), Enabled: str(m, "Status") == "1", Version: str(m, "UpdateTime")}
	}
}
func (x *formProvider) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	path := ""
	p := url.Values{}
	rowsKey := ""
	switch x.kind {
	case "namesilo":
		path = "/dnsListRecords"
		p.Set("domain", x.zoneName)
		rowsKey = "resource_record"
	case "west":
		path = "/domain/"
		p = url.Values{"act": {"getdnsrecord"}, "domain": {x.zoneName}, "type": {o.Type}, "line": {o.Line}, "host": {o.Keyword}, "value": {o.Value}, "pageno": {strconv.Itoa(o.Page)}, "limit": {strconv.Itoa(o.PageSize)}}
		if o.Name != "" {
			p.Set("host", o.Name)
		}
		rowsKey = "items"
	case "dnsmgr":
		path = "/api/record/data/" + pathID(x.zoneID)
		p = url.Values{"offset": {strconv.Itoa((o.Page - 1) * o.PageSize)}, "limit": {strconv.Itoa(o.PageSize)}, "keyword": {o.Keyword}, "subdomain": {o.Name}, "value": {o.Value}, "type": {o.Type}, "line": {o.Line}}
		if o.Enabled != nil {
			p.Set("status", map[bool]string{true: "1", false: "0"}[*o.Enabled])
		}
		rowsKey = "rows"
	}
	out, err := x.call(ctx, path, p)
	if err != nil {
		return RecordPage{}, err
	}
	rows := []Record{}
	for _, m := range arr(out, rowsKey) {
		rows = append(rows, x.normalize(m))
	}
	if x.kind == "namesilo" {
		return recordPage(rows, o), nil
	}
	return RecordPage{Total: integer(out, "total"), Rows: rows}, nil
}
func (x *formProvider) GetRecord(ctx context.Context, id string) (Record, error) {
	for page := 1; page < 1000; page++ {
		out, err := x.ListRecords(ctx, ListOptions{Page: page, PageSize: 100})
		if err != nil {
			return Record{}, err
		}
		for _, r := range out.Rows {
			if r.ID == id {
				return r, nil
			}
		}
		if page*100 >= out.Total {
			break
		}
	}
	return Record{}, ErrNotFound
}
func (x *formProvider) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := x.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	p := url.Values{}
	path := ""
	switch x.kind {
	case "namesilo":
		path = "/dnsAddRecord"
		if r.Name == "@" {
			r.Name = ""
		}
		p = url.Values{"domain": {x.zoneName}, "rrtype": {r.Type}, "rrhost": {r.Name}, "rrvalue": {r.Value}, "rrttl": {strconv.Itoa(r.TTL)}}
		if id != "" {
			path = "/dnsUpdateRecord"
			p.Set("rrid", id)
		}
		if r.Priority != nil {
			p.Set("rrdistance", strconv.Itoa(*r.Priority))
		}
	case "west":
		path = "/domain/"
		act := "adddnsrecord"
		if id != "" {
			act = "moddnsrecord"
		}
		p = url.Values{"act": {act}, "domain": {x.zoneName}, "host": {r.Name}, "type": {r.Type}, "value": {r.Value}, "ttl": {strconv.Itoa(r.TTL)}, "line": {r.Line}}
		if id != "" {
			p.Set("id", id)
		}
		if r.Priority != nil {
			p.Set("level", strconv.Itoa(*r.Priority))
		}
	case "dnsmgr":
		act := "add"
		if id != "" {
			act = "update"
		}
		path = "/api/record/" + act + "/" + pathID(x.zoneID)
		p = url.Values{"name": {r.Name}, "type": {r.Type}, "value": {r.Value}, "line": {r.Line}, "ttl": {strconv.Itoa(r.TTL)}, "remark": {r.Remark}}
		if id != "" {
			p.Set("recordid", id)
		}
		if r.Priority != nil {
			p.Set("mx", strconv.Itoa(*r.Priority))
		}
		if r.Weight != nil {
			p.Set("weight", strconv.Itoa(*r.Weight))
		}
	}
	out, err := x.call(ctx, path, p)
	if err != nil {
		return Record{}, err
	}
	if writtenID := firstString(out, "record_id", "recordid", "id"); writtenID != "remote request rejected" {
		id = writtenID
	}
	if id == "" {
		id = firstString(out, "record_id", "recordid", "id")
		if id == "remote request rejected" {
			for page := 1; page < 1000; page++ {
				records, err := x.ListRecords(ctx, ListOptions{Page: page, PageSize: 100, Name: r.Name, Type: r.Type, Value: r.Value})
				if err != nil {
					return Record{}, acceptedWriteError(x.kind, err)
				}
				for _, got := range records.Rows {
					if got.Name == r.Name && got.Type == r.Type && got.Value == r.Value {
						id = got.ID
						break
					}
				}
				if id != "remote request rejected" || page*100 >= records.Total {
					break
				}
			}
		}
	}
	if id == "" || id == "remote request rejected" {
		return r, responseError(x.kind, 200, true, "record created but provider did not return its ID")
	}
	r.ID = id
	if r.Name == "" {
		r.Name = "@"
	}
	if x.kind != "namesilo" && (id != "" || !r.Enabled) {
		if err = x.SetStatus(ctx, id, r.Enabled); err != nil {
			return r, acceptedWriteError(x.kind, err)
		}
	}
	return r, nil
}
func (x *formProvider) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return x.write(ctx, "", r)
}
func (x *formProvider) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return x.write(ctx, id, r)
}
func (x *formProvider) DeleteRecord(ctx context.Context, id string) error {
	path := ""
	p := url.Values{}
	switch x.kind {
	case "namesilo":
		path = "/dnsDeleteRecord"
		p = url.Values{"domain": {x.zoneName}, "rrid": {id}}
	case "west":
		path = "/domain/"
		p = url.Values{"act": {"deldnsrecord"}, "domain": {x.zoneName}, "id": {id}}
	case "dnsmgr":
		path = "/api/record/delete/" + pathID(x.zoneID)
		p.Set("recordid", id)
	}
	_, err := x.call(ctx, path, p)
	return err
}
func (x *formProvider) SetStatus(ctx context.Context, id string, enabled bool) error {
	if x.kind == "namesilo" {
		return ErrCapability
	}
	path := "/domain/"
	p := url.Values{"act": {"pause"}, "domain": {x.zoneName}, "id": {id}, "val": {map[bool]string{true: "0", false: "1"}[enabled]}}
	if x.kind == "dnsmgr" {
		path = "/api/record/status/" + pathID(x.zoneID)
		p = url.Values{"recordid": {id}, "status": {map[bool]string{true: "1", false: "0"}[enabled]}}
	}
	_, err := x.call(ctx, path, p)
	return err
}
func (x *formProvider) SetRemark(ctx context.Context, id, remark string) error {
	if x.kind != "dnsmgr" {
		return ErrCapability
	}
	_, err := x.call(ctx, "/api/record/remark/"+pathID(x.zoneID), url.Values{"recordid": {id}, "remark": {remark}})
	return err
}
func (x *formProvider) Lines(ctx context.Context) ([]Line, error) {
	if x.kind == "namesilo" {
		return x.base.Lines(ctx)
	}
	if x.kind == "west" {
		return []Line{{ID: "", Name: "默认"}, {ID: "LTEL", Name: "电信"}, {ID: "LCNC", Name: "联通"}, {ID: "LMOB", Name: "移动"}, {ID: "LEDU", Name: "教育网"}, {ID: "LSEO", Name: "搜索引擎"}, {ID: "LFOR", Name: "境外"}}, nil
	}
	out, err := x.call(ctx, "/api/domain/"+pathID(x.zoneID), url.Values{"loginurl": {"0"}})
	if err != nil {
		return nil, err
	}
	rows := []Line{}
	for _, l := range arr(out, "recordLine") {
		rows = append(rows, Line{ID: str(l, "id"), Name: str(l, "name"), Parent: str(l, "parent")})
	}
	return rows, nil
}
func (x *formProvider) MinTTL(ctx context.Context) (int, error) {
	if x.kind == "namesilo" {
		return 3600, nil
	}
	if x.kind == "west" {
		return 1, nil
	}
	out, err := x.call(ctx, "/api/domain/"+pathID(x.zoneID), url.Values{"loginurl": {"0"}})
	if err != nil {
		return 0, err
	}
	return integer(out, "minTTL"), nil
}

var _ Provider = (*formProvider)(nil)
