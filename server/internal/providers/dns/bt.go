package dns

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type btDNS struct{ *base }

func (b *btDNS) call(ctx context.Context, path string, p map[string]any) (any, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	stamp := strconv.FormatInt(b.now().Unix(), 10)
	signature := hex.EncodeToString(hmac256([]byte(b.cfg["SecretKey"]), b.cfg["AccountID"]+"\n"+stamp+"\nPOST\n"+path+"\n"+string(body)))
	headers := http.Header{"Content-Type": {"application/json"}, "X-Account-ID": {b.cfg["AccountID"]}, "X-Access-Key": {b.cfg["AccessKey"]}, "X-Timestamp": {stamp}, "X-Signature": {signature}}
	raw, status, err := b.raw(ctx, "POST", path, nil, body, headers)
	if err != nil {
		return nil, classifyProtocolError(err, !strings.Contains(path, "/list") && !strings.Contains(path, "/get"))
	}
	var out map[string]any
	mutation := !strings.Contains(path, "/list") && !strings.Contains(path, "/get")
	if err = decodeJSON(raw, &out); err != nil || out == nil {
		return nil, responseError(b.kind, status, mutation, "invalid BT JSON response")
	}
	if _, ok := out["code"]; !ok {
		return nil, responseError(b.kind, status, mutation, "missing BT result code")
	}
	if status >= 400 || integer(out, "code") != 0 {
		return nil, &RemoteError{Provider: b.kind, Status: status, Code: str(out, "code"), Message: str(out, "msg"), UnknownResult: status >= 500 && mutation}
	}
	return out["data"], nil
}
func (b *btDNS) domainParams() map[string]any {
	parts := strings.Split(b.zoneID, "|")
	id, _ := strconv.Atoi(parts[0])
	typ := 1
	if len(parts) > 1 {
		typ, _ = strconv.Atoi(parts[1])
	}
	return map[string]any{"domain_id": id, "domain_type": typ}
}
func (b *btDNS) Validate(ctx context.Context) error {
	_, err := b.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (b *btDNS) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	data, err := b.call(ctx, "/api/v1/dns/manage/list_domains", map[string]any{"p": o.Page, "rows": o.PageSize, "keyword": o.Keyword})
	if err != nil {
		return DomainPage{}, err
	}
	out := mapData(data)
	rows := []Domain{}
	for _, d := range arr(out, "data") {
		rows = append(rows, Domain{ID: str(d, "local_id") + "|" + str(d, "domain_type"), Name: str(d, "full_domain"), RecordCount: integer(d, "record_count")})
	}
	return DomainPage{Total: integer(out, "total"), Rows: rows}, nil
}
func (b *btDNS) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	data, err := b.call(ctx, "/api/v1/dns/manage/add_external_domain", map[string]any{"full_domain": name})
	if err != nil {
		return Domain{}, err
	}
	m := mapData(data)
	return Domain{ID: str(m, "domain_id"), Name: str(m, "full_domain")}, nil
}
func (b *btDNS) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	p := b.domainParams()
	p["p"] = o.Page
	p["rows"] = o.PageSize
	key, value := "", ""
	switch {
	case o.Name != "":
		key, value = "record", o.Name
	case o.Keyword != "":
		key, value = "record", o.Keyword
	case o.Value != "":
		key, value = "value", o.Value
	case o.Type != "":
		key, value = "type", o.Type
	case o.Enabled != nil:
		key, value = "state", map[bool]string{true: "0", false: "1"}[*o.Enabled]
	case o.Line != "":
		key, value = "line", o.Line
	}
	if key != "" {
		p["searchKey"] = key
		p["searchValue"] = value
	}
	data, err := b.call(ctx, "/api/v1/dns/record/list", p)
	if err != nil {
		return RecordPage{}, err
	}
	out := mapData(data)
	rows := []Record{}
	for _, r := range arr(out, "data") {
		rows = append(rows, Record{ID: str(r, "record_id"), Name: str(r, "record"), Type: str(r, "type"), Value: str(r, "value"), Line: str(r, "viewID"), TTL: integer(r, "TTL"), Priority: optionalInt(r, "MX"), Weight: optionalInt(r, "MX"), Remark: str(r, "remark"), Enabled: integer(r, "state") != 1, Version: str(r, "created_at")})
	}
	return RecordPage{Total: integer(out, "count"), Rows: rows}, nil
}
func (b *btDNS) GetRecord(ctx context.Context, id string) (Record, error) {
	for page := 1; page < 1000; page++ {
		out, err := b.ListRecords(ctx, ListOptions{Page: page, PageSize: 100})
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
func (b *btDNS) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := b.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	p := b.domainParams()
	p["type"] = r.Type
	p["record"] = r.Name
	p["value"] = r.Value
	p["ttl"] = r.TTL
	p["remark"] = r.Remark
	line, _ := strconv.Atoi(r.Line)
	p["view_id"] = line
	weight := 1
	if r.Weight != nil {
		weight = *r.Weight
	}
	p["mx"] = weight
	if r.Type == "MX" {
		p["mx"] = *r.Priority
	}
	action := "create"
	if id != "" {
		action = "update"
		p["record_id"] = id
	}
	data, err := b.call(ctx, "/api/v1/dns/record/"+action, p)
	if err != nil {
		return Record{}, err
	}
	if writtenID := firstString(mapData(data), "record_id", "id"); writtenID != "remote request rejected" {
		id = writtenID
	}
	if id == "" {
		m := mapData(data)
		id = firstString(m, "record_id", "id")
		if id == "remote request rejected" {
			out, err := b.ListRecords(ctx, ListOptions{PageSize: 1000, Name: r.Name})
			if err != nil {
				return r, acceptedWriteError(b.kind, err)
			}
			for _, got := range out.Rows {
				if got.Name == r.Name && got.Type == r.Type && got.Value == r.Value {
					id = got.ID
					break
				}
			}
		}
	}
	if id == "remote request rejected" || id == "" {
		return r, responseError(b.kind, 200, true, "record created but ID not found")
	}
	r.ID = id
	if id != "" || !r.Enabled {
		err = b.SetStatus(ctx, id, r.Enabled)
	}
	return r, acceptedWriteError(b.kind, err)
}
func (b *btDNS) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return b.write(ctx, "", r)
}
func (b *btDNS) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return b.write(ctx, id, r)
}
func (b *btDNS) DeleteRecord(ctx context.Context, id string) error {
	p := b.domainParams()
	p["id"] = id
	_, err := b.call(ctx, "/api/v1/dns/record/delete", p)
	return err
}
func (b *btDNS) SetStatus(ctx context.Context, id string, enabled bool) error {
	p := b.domainParams()
	p["record_id"] = id
	action := "pause"
	if enabled {
		action = "start"
	}
	_, err := b.call(ctx, "/api/v1/dns/record/"+action, p)
	return err
}
func (b *btDNS) SetRemark(ctx context.Context, id, remark string) error {
	r, err := b.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Remark = remark
	_, err = b.UpdateRecord(ctx, id, r)
	return err
}
func (b *btDNS) Lines(ctx context.Context) ([]Line, error) {
	data, err := b.call(ctx, "/api/v1/dns/record/get_views", map[string]any{})
	if err != nil {
		return nil, err
	}
	rows := []Line{}
	var visit func([]map[string]any, string)
	visit = func(ls []map[string]any, parent string) {
		for _, l := range ls {
			if boolean(l, "free") {
				id := str(l, "viewId")
				rows = append(rows, Line{ID: id, Name: str(l, "name"), Parent: parent})
				visit(arr(l, "children"), id)
			}
		}
	}
	visit(listData(data), "")
	return rows, nil
}
func (b *btDNS) MinTTL(context.Context) (int, error) { return 300, nil }

var _ Provider = (*btDNS)(nil)
