package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

type cloudREST struct{ *base }

func (c *cloudREST) path() string {
	if c.kind == "huawei" {
		return "/v2.1/zones/" + pathID(c.zoneID) + "/recordsets"
	}
	return "/v1/dns/zone/" + pathID(c.zoneName) + "/record"
}
func (c *cloudREST) Validate(ctx context.Context) error {
	_, err := c.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (c *cloudREST) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	path := "/v2/zones"
	q := queryValues(map[string]any{"name": o.Keyword, "offset": (o.Page - 1) * o.PageSize, "limit": o.PageSize})
	if c.kind == "baidu" {
		path = "/v1/dns/zone"
		q = queryValues(map[string]any{"name": o.Keyword})
	}
	out, err := c.signed(ctx, "GET", path, q, nil)
	if err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	for _, d := range arr(out, "zones") {
		rows = append(rows, Domain{ID: str(d, "id"), Name: strings.TrimSuffix(str(d, "name"), "."), RecordCount: integer(d, "record_num")})
	}
	if c.kind == "baidu" {
		return domainPage(rows, o), nil
	}
	return DomainPage{Total: integer(obj(out, "metadata"), "total_count"), Rows: rows}, nil
}
func (c *cloudREST) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	path := "/v2/zones"
	body := map[string]any{"name": name}
	if c.kind == "baidu" {
		path = "/v1/dns/zone"
		body["clientToken"] = nonce()
	}
	out, err := c.signed(ctx, "POST", path, nil, body)
	if err != nil {
		return Domain{}, err
	}
	if id := str(out, "id"); id != "" {
		return Domain{ID: id, Name: name}, nil
	}
	if c.kind == "baidu" {
		out, err = c.signed(ctx, "GET", path, url.Values{"name": {name}}, nil)
		if err != nil {
			return Domain{}, err
		}
		for _, d := range arr(out, "zones") {
			if strings.EqualFold(strings.TrimSuffix(str(d, "name"), "."), name) {
				return Domain{ID: str(d, "id"), Name: name}, nil
			}
		}
	}
	return Domain{}, errors.New("provider omitted created zone ID")
}
func (c *cloudREST) normalize(d map[string]any) Record {
	if c.kind == "baidu" {
		name := str(d, "rr")
		if name == "" {
			name = relative(str(d, "name"), c.zoneName)
		}
		return Record{ID: str(d, "id"), Name: name, Type: str(d, "type"), Value: str(d, "value"), Line: str(d, "line"), TTL: integer(d, "ttl"), Priority: optionalInt(d, "priority"), Enabled: str(d, "status") == "running", Remark: str(d, "description")}
	}
	values := stringValues(d, "records")
	value := ""
	if len(values) > 0 {
		value = values[0]
	}
	r := Record{ID: str(d, "id"), Name: relative(str(d, "name"), c.zoneName), Type: str(d, "type"), Value: value, Values: values, Line: str(d, "line"), TTL: integer(d, "ttl"), Priority: optionalInt(d, "mx"), Weight: optionalInt(d, "weight"), Enabled: str(d, "status") == "ACTIVE", Remark: str(d, "description"), Version: str(d, "updated_at")}
	if r.Type == "MX" && r.Priority == nil {
		parsed := []string{}
		for _, value := range values {
			parts := strings.SplitN(value, " ", 2)
			if len(parts) != 2 {
				parsed = nil
				break
			}
			priority, err := strconv.Atoi(parts[0])
			if err != nil {
				parsed = nil
				break
			}
			if r.Priority == nil {
				r.Priority = &priority
			}
			parsed = append(parsed, strings.TrimSuffix(parts[1], "."))
		}
		if len(parsed) > 0 {
			r.Values = parsed
			r.Value = parsed[0]
		}
		r.Metadata = jsonRaw(d)
	}
	if r.Type == "TXT" {
		for i, v := range r.Values {
			r.Values[i] = strings.Trim(v, "\"")
		}
		if len(r.Values) > 0 {
			r.Value = r.Values[0]
		}
	}
	return r
}
func (c *cloudREST) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	q := url.Values{}
	if c.kind == "huawei" {
		q = queryValues(map[string]any{"offset": (o.Page - 1) * o.PageSize, "limit": o.PageSize, "type": o.Type, "line_id": o.Line, "name": o.Keyword, "records": o.Value})
		if o.Name != "" {
			q.Set("name", absolute(o.Name, c.zoneName)+".")
			q.Set("search_mode", "equal")
		}
		if o.Enabled != nil {
			q.Set("status", map[bool]string{true: "ACTIVE", false: "DISABLE"}[*o.Enabled])
		}
		if s := map[string]string{"Name": "name", "Type": "type", "UpdateTime": "updated_at"}[o.Sort]; s != "" {
			q.Set("sort_key", s)
			q.Set("sort_dir", map[bool]string{true: "desc", false: "asc"}[o.Desc])
		}
	} else if o.Name != "" {
		q.Set("rr", o.Name)
	}
	out, err := c.signed(ctx, "GET", c.path(), q, nil)
	if err != nil {
		return RecordPage{}, err
	}
	key := "recordsets"
	if c.kind == "baidu" {
		key = "records"
	}
	rows := []Record{}
	for _, d := range arr(out, key) {
		rows = append(rows, c.normalize(d))
	}
	if c.kind == "baidu" {
		return recordPage(rows, o), nil
	}
	return RecordPage{Total: integer(obj(out, "metadata"), "total_count"), Rows: rows}, nil
}
func (c *cloudREST) GetRecord(ctx context.Context, id string) (Record, error) {
	path := c.path() + "/" + pathID(id)
	var q url.Values
	if c.kind == "baidu" {
		path = c.path()
		q = url.Values{"id": {id}}
	}
	out, err := c.signed(ctx, "GET", path, q, nil)
	if err != nil {
		return Record{}, err
	}
	if c.kind == "baidu" {
		for _, d := range arr(out, "records") {
			if str(d, "id") == id {
				return c.normalize(d), nil
			}
		}
		return Record{}, ErrNotFound
	}
	if str(out, "id") == "" {
		return Record{}, ErrNotFound
	}
	if str(out, "id") == "" || str(out, "type") == "" {
		return Record{}, responseError(c.kind, 200, false, "missing Huawei record detail")
	}
	return c.normalize(out), nil
}
func (c *cloudREST) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := c.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	if id != "" && (r.Version != "" || c.kind == "huawei") {
		current, err := c.GetRecord(ctx, id)
		if err != nil {
			return Record{}, err
		}
		if r.Version != "" && current.Version != r.Version {
			return Record{}, ErrConflict
		}
		if c.kind == "huawei" && current.Type == "MX" {
			var metadata map[string]any
			_ = json.Unmarshal(current.Metadata, &metadata)
			priority := ""
			for _, value := range stringValues(metadata, "records") {
				parts := strings.SplitN(value, " ", 2)
				if len(parts) == 2 {
					if priority != "" && priority != parts[0] {
						return Record{}, errors.New("mixed-priority MX RRset requires explicit provider editing")
					}
					priority = parts[0]
				}
			}
		}
		if c.kind == "huawei" && current.Name == r.Name && current.Type == r.Type && len(r.Values) == 0 && len(current.Values) > 1 {
			r.Values = append([]string(nil), current.Values...)
			r.Values[0] = r.Value
		}
	}
	method, path := "POST", c.path()
	if id != "" {
		method = "PUT"
		path += "/" + pathID(id)
	}
	p := map[string]any{}
	var q url.Values
	if c.kind == "huawei" {
		name, err := asciiRecordName(r.Name, c.zoneName)
		if err != nil {
			return Record{}, err
		}
		values := append([]string(nil), r.Values...)
		if len(values) > 0 && r.Value != "" {
			values[0] = r.Value
		}
		if len(values) == 0 {
			values = []string{r.Value}
		}
		if r.Type == "TXT" {
			for i, v := range values {
				if !strings.HasPrefix(v, "\"") {
					values[i] = "\"" + v + "\""
				}
			}
		}
		if r.Type == "MX" {
			for i, v := range values {
				values[i] = strconv.Itoa(*r.Priority) + " " + v
			}
		}
		line := r.Line
		if line == "" || line == "0" || line == "default" {
			line = "default_view"
		}
		p = map[string]any{"name": name + ".", "type": r.Type, "records": values, "line": line, "ttl": r.TTL, "description": r.Remark}
		if r.Weight != nil {
			p["weight"] = *r.Weight
		}
	} else {
		p = map[string]any{"rr": r.Name, "type": r.Type, "value": r.Value, "line": r.Line, "ttl": r.TTL, "description": r.Remark}
		if r.Priority != nil {
			p["priority"] = *r.Priority
		}
		q = url.Values{"clientToken": {nonce()}}
	}
	out, err := c.signed(ctx, method, path, q, p)
	if err != nil {
		return Record{}, err
	}
	if id == "" {
		id = firstString(out, "id", "recordId")
		if id == "remote request rejected" {
			id = ""
		}
	}
	if id == "" {
		page, err := c.ListRecords(ctx, ListOptions{Name: r.Name, Type: r.Type, Value: r.Value, PageSize: 1000})
		if err != nil {
			return Record{}, acceptedWriteError(c.kind, err)
		}
		for _, row := range page.Rows {
			if row.Value == r.Value {
				id = row.ID
				break
			}
		}
	}
	if id == "" {
		return Record{}, responseError(c.kind, 200, true, "created record ID could not be reconciled")
	}
	r.ID = id
	if c.kind == "huawei" || !r.Enabled {
		if err = c.SetStatus(ctx, id, r.Enabled); err != nil {
			return r, acceptedWriteError(c.kind, err)
		}
	}
	return r, nil
}
func (c *cloudREST) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return c.write(ctx, "", r)
}
func (c *cloudREST) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return c.write(ctx, id, r)
}
func (c *cloudREST) DeleteRecord(ctx context.Context, id string) error {
	var q url.Values
	if c.kind == "baidu" {
		q = url.Values{"clientToken": {nonce()}}
	}
	_, err := c.signed(ctx, "DELETE", c.path()+"/"+pathID(id), q, nil)
	return err
}
func (c *cloudREST) SetStatus(ctx context.Context, id string, on bool) error {
	path := c.path() + "/" + pathID(id)
	var q url.Values
	var p any
	if c.kind == "huawei" {
		path = "/v2.1/recordsets/" + pathID(id) + "/statuses/set"
		p = map[string]any{"status": map[bool]string{true: "ENABLE", false: "DISABLE"}[on]}
	} else {
		q = url.Values{map[bool]string{true: "enable", false: "disable"}[on]: {""}, "clientToken": {nonce()}}
	}
	_, err := c.signed(ctx, "PUT", path, q, p)
	return err
}
func (c *cloudREST) SetRemark(ctx context.Context, id, remark string) error {
	r, err := c.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Remark = remark
	_, err = c.write(ctx, id, r)
	return err
}
func (c *cloudREST) Lines(context.Context) ([]Line, error) {
	if c.kind == "huawei" {
		return huaweiLines(), nil
	}
	return []Line{{ID: "default", Name: "默认"}, {ID: "ct", Name: "电信"}, {ID: "cnc", Name: "联通"}, {ID: "cmnet", Name: "移动"}, {ID: "edu", Name: "教育网"}, {ID: "search", Name: "搜索引擎(百度)"}}, nil
}

var _ Provider = (*cloudREST)(nil)
