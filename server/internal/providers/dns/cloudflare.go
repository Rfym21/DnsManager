package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type cloudflare struct{ *base }

func (c *cloudflare) request(ctx context.Context, method, path string, q url.Values, body any) (map[string]any, error) {
	key := c.cfg["apikey"]
	if c.cfg["api_token"] != "" {
		key = c.cfg["api_token"]
	}
	if key == "" {
		return nil, errors.New("Cloudflare API credential is required")
	}
	headers := http.Header{}
	auth := c.cfg["auth"]
	if auth == "0" || auth == "global" {
		if c.cfg["email"] == "" {
			return nil, errors.New("Cloudflare global key requires email")
		}
		headers.Set("X-Auth-Email", c.cfg["email"])
		headers.Set("X-Auth-Key", key)
	} else {
		headers.Set("Authorization", "Bearer "+key)
	}
	res, status, err := c.json(ctx, method, path, q, body, headers)
	if err != nil {
		return nil, err
	}
	if _, ok := res["success"].(bool); !ok {
		return nil, responseError(c.kind, status, methodWrites(method), "missing Cloudflare result status")
	}
	if !boolean(res, "success") {
		errs := arr(res, "errors")
		if len(errs) > 0 {
			return nil, &RemoteError{Provider: c.kind, Status: status, Code: str(errs[0], "code"), Message: str(errs[0], "message")}
		}
		return nil, &RemoteError{Provider: c.kind, Status: status, Message: "Cloudflare response was not successful"}
	}
	return res, nil
}
func (c *cloudflare) Validate(ctx context.Context) error {
	_, err := c.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (c *cloudflare) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	q := url.Values{"per_page": {"50"}}
	if o.Keyword != "" {
		q.Set("name", o.Keyword)
	}
	rows := []Domain{}
	start := (o.Page - 1) * o.PageSize
	first, total := start/50+1, 0
	for page := first; page <= first+(o.PageSize+49)/50; page++ {
		q.Set("page", strconv.Itoa(page))
		res, err := c.request(ctx, "GET", "/zones", q, nil)
		if err != nil {
			return DomainPage{}, err
		}
		total = integer(obj(res, "result_info"), "total_count")
		for _, z := range arr(res, "result") {
			rows = append(rows, Domain{ID: str(z, "id"), Name: str(z, "name")})
		}
		if page*50 >= total || len(rows) >= start%50+o.PageSize {
			break
		}
	}
	offset := min(start%50, len(rows))
	end := min(offset+o.PageSize, len(rows))
	return DomainPage{Total: total, Rows: rows[offset:end]}, nil
}
func (c *cloudflare) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	body := map[string]any{"name": name, "jump_start": false}
	if a := c.cfg["account_id"]; a != "" {
		body["account"] = map[string]string{"id": a}
	}
	res, err := c.request(ctx, "POST", "/zones", nil, body)
	if err != nil {
		return Domain{}, err
	}
	z := obj(res, "result")
	return Domain{ID: str(z, "id"), Name: str(z, "name")}, nil
}
func (c *cloudflare) normalize(z map[string]any) Record {
	name := relative(str(z, "name"), c.zoneName)
	enabled := !strings.HasSuffix(name, "_pause")
	if !enabled {
		name = strings.TrimSuffix(name, "_pause")
	}
	if name == "__root__" {
		name = "@"
	}
	value := str(z, "content")
	if str(z, "type") == "SRV" {
		d := obj(z, "data")
		if len(d) > 0 {
			value = fmt.Sprintf("%d %d %d %s", integer(d, "priority"), integer(d, "weight"), integer(d, "port"), strings.TrimSuffix(str(d, "target"), "."))
		}
	}
	return Record{ID: str(z, "id"), Name: name, Type: str(z, "type"), Value: value, Line: map[bool]string{true: "1", false: "0"}[boolean(z, "proxied")], TTL: integer(z, "ttl"), Priority: optionalInt(z, "priority"), Remark: str(z, "comment"), Enabled: enabled, Proxied: boolean(z, "proxied"), Version: str(z, "modified_on"), Metadata: jsonRaw(z["data"])}
}
func (c *cloudflare) recordPath(id string) string {
	path := "/zones/" + pathID(c.zoneID) + "/dns_records"
	if id != "" {
		path += "/" + pathID(id)
	}
	return path
}
func (c *cloudflare) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	q := url.Values{"page": {strconv.Itoa(o.Page)}, "per_page": {strconv.Itoa(o.PageSize)}}
	if o.Keyword != "" {
		q.Set("search", o.Keyword)
	}
	if o.Value != "" {
		q.Set("search", o.Value)
	}
	if o.Type != "" {
		q.Set("type", o.Type)
	}
	if o.Name != "" {
		name, err := asciiRecordName(o.Name, c.zoneName)
		if err != nil {
			return RecordPage{}, err
		}
		q.Set("name", name)
	}
	if o.Line != "" {
		q.Set("proxied", strconv.FormatBool(o.Line == "1"))
	}
	sort := map[string]string{"Name": "name", "Type": "type", "Value": "content", "LineName": "proxied"}[o.Sort]
	if sort != "" {
		q.Set("order", sort)
		q.Set("direction", map[bool]string{true: "desc", false: "asc"}[o.Desc])
	}
	res, err := c.request(ctx, "GET", c.recordPath(""), q, nil)
	if err != nil {
		return RecordPage{}, err
	}
	rows := []Record{}
	for _, r := range arr(res, "result") {
		rows = append(rows, c.normalize(r))
	}
	return RecordPage{Total: integer(obj(res, "result_info"), "total_count"), Rows: rows}, nil
}
func (c *cloudflare) GetRecord(ctx context.Context, id string) (Record, error) {
	res, err := c.request(ctx, "GET", c.recordPath(id), nil, nil)
	if err != nil {
		return Record{}, err
	}
	return c.normalize(obj(res, "result")), nil
}
func (c *cloudflare) write(ctx context.Context, method, id string, r Record) (Record, error) {
	if prepared, err := c.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	name, err := asciiRecordName(r.Name, c.zoneName)
	if err != nil {
		return Record{}, err
	}
	if !r.Enabled {
		host := r.Name
		if host == "@" {
			host = "__root__"
		}
		name, err = asciiRecordName(host+"_pause", c.zoneName)
		if err != nil {
			return Record{}, err
		}
	}
	typ := strings.ToUpper(r.Type)
	if typ == "SPF" {
		typ = "TXT"
	}
	body := map[string]any{"name": name, "type": typ, "content": r.Value, "ttl": r.TTL, "comment": r.Remark}
	if typ == "A" || typ == "AAAA" || typ == "CNAME" {
		body["proxied"] = r.Proxied || r.Line == "1"
	}
	if r.Priority != nil {
		body["priority"] = *r.Priority
	}
	if typ == "SRV" {
		p := strings.Fields(r.Value)
		if len(p) != 4 {
			return Record{}, errors.New("SRV requires priority weight port target")
		}
		priority, e1 := strconv.Atoi(p[0])
		weight, e2 := strconv.Atoi(p[1])
		port, e3 := strconv.Atoi(p[2])
		target, e4 := CanonicalName(p[3])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			return Record{}, errors.New("invalid SRV fields")
		}
		body["data"] = map[string]any{"priority": priority, "weight": weight, "port": port, "target": target}
		delete(body, "content")
	}
	if typ == "CAA" {
		p := strings.SplitN(r.Value, " ", 3)
		if len(p) != 3 {
			return Record{}, errors.New("CAA requires flags tag value")
		}
		flags, err := strconv.Atoi(p[0])
		if err != nil || flags < 0 || flags > 255 {
			return Record{}, errors.New("CAA flags must be 0–255")
		}
		body["data"] = map[string]any{"flags": flags, "tag": p[1], "value": strings.Trim(p[2], "\"")}
		delete(body, "content")
	}
	if r.Version != "" && id != "" {
		current, err := c.GetRecord(ctx, id)
		if err != nil {
			return Record{}, err
		}
		if current.Version != r.Version {
			return Record{}, ErrConflict
		}
	}
	res, err := c.request(ctx, method, c.recordPath(id), nil, body)
	if err != nil {
		return Record{}, err
	}
	result := obj(res, "result")
	if str(result, "id") == "" {
		return Record{}, responseError(c.kind, 200, true, "Cloudflare omitted written record ID")
	}
	return c.normalize(result), nil
}
func (c *cloudflare) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return c.write(ctx, "POST", "", r)
}
func (c *cloudflare) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return c.write(ctx, "PATCH", id, r)
}
func (c *cloudflare) DeleteRecord(ctx context.Context, id string) error {
	_, err := c.request(ctx, "DELETE", c.recordPath(id), nil, nil)
	return err
}
func (c *cloudflare) SetStatus(ctx context.Context, id string, enabled bool) error {
	r, err := c.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Enabled = enabled
	r.Version = ""
	_, err = c.UpdateRecord(ctx, id, r)
	return err
}
func (c *cloudflare) SetRemark(ctx context.Context, id, remark string) error {
	_, err := c.request(ctx, "PATCH", c.recordPath(id), nil, map[string]string{"comment": remark})
	return err
}
func (c *cloudflare) Lines(context.Context) ([]Line, error) {
	return []Line{{ID: "0", Name: "仅DNS"}, {ID: "1", Name: "代理"}}, nil
}
func (c *cloudflare) MinTTL(context.Context) (int, error) { return 1, nil }

var _ Provider = (*cloudflare)(nil)
var _ = json.RawMessage{}
