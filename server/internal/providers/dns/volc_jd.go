package dns

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

type cloudAction struct{ *base }

func (c *cloudAction) call(ctx context.Context, method, action string, p map[string]any) (map[string]any, error) {
	if c.kind == "huoshan" {
		q := queryValues(map[string]any{"Action": action, "Version": "2018-08-01"})
		if method == "GET" {
			for k, vals := range queryValues(p) {
				q[k] = vals
			}
			return c.signed(ctx, method, "/", q, nil)
		}
		return c.signed(ctx, method, "/", q, p)
	}
	path := "/v2/regions/cn-north-1" + action
	if method == "GET" || method == "DELETE" {
		return c.signed(ctx, method, path, queryValues(p), nil)
	}
	return c.signed(ctx, method, path, nil, p)
}
func (c *cloudAction) Validate(ctx context.Context) error {
	_, err := c.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (c *cloudAction) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	action := "ListZones"
	p := map[string]any{"PageNumber": o.Page, "PageSize": o.PageSize, "Key": o.Keyword}
	if c.kind == "jdcloud" {
		action = "/domain"
		p = map[string]any{"pageNumber": o.Page, "pageSize": o.PageSize, "domainName": o.Keyword}
	}
	out, err := c.call(ctx, "GET", action, p)
	if err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	key, total := "Zones", integer(out, "Total")
	if c.kind == "jdcloud" {
		key, total = "dataList", integer(out, "totalCount")
	}
	for _, d := range arr(out, key) {
		if c.kind == "huoshan" {
			rows = append(rows, Domain{ID: str(d, "ZID"), Name: str(d, "ZoneName"), RecordCount: integer(d, "RecordCount")})
		} else {
			rows = append(rows, Domain{ID: str(d, "id"), Name: str(d, "domainName")})
		}
	}
	return DomainPage{Total: total, Rows: rows}, nil
}
func (c *cloudAction) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	if c.kind == "huoshan" {
		out, err := c.call(ctx, "POST", "CreateZone", map[string]any{"ZoneName": name})
		if err != nil {
			return Domain{}, err
		}
		return Domain{ID: str(out, "ZID"), Name: str(out, "ZoneName")}, nil
	}
	out, err := c.call(ctx, "POST", "/domain", map[string]any{"packId": 0, "domainName": name})
	if err != nil {
		return Domain{}, err
	}
	d := obj(out, "data")
	return Domain{ID: str(d, "id"), Name: str(d, "domainName")}, nil
}
func jdType(t string, to bool) string {
	m := map[string]string{"REDIRECT_URL": "EXPLICIT_URL", "FORWARD_URL": "IMPLICIT_URL"}
	if to {
		if s := m[t]; s != "" {
			return s
		}
	} else {
		for a, b := range m {
			if b == t {
				return a
			}
		}
	}
	return t
}
func (c *cloudAction) normalize(d map[string]any) Record {
	if c.kind == "huoshan" {
		r := Record{ID: str(d, "RecordID"), Name: str(d, "Host"), Type: str(d, "Type"), Value: str(d, "Value"), Line: str(d, "Line"), TTL: integer(d, "TTL"), Weight: optionalInt(d, "Weight"), Remark: str(d, "Remark"), Enabled: boolean(d, "Enable"), Version: str(d, "UpdatedAt")}
		if r.Type == "MX" {
			parts := strings.SplitN(r.Value, " ", 2)
			if len(parts) == 2 {
				n, _ := strconv.Atoi(parts[0])
				r.Priority = &n
				r.Value = parts[1]
			}
		}
		return r
	}
	line := "0"
	if a, ok := d["viewValue"].([]any); ok && len(a) > 0 {
		line = str(map[string]any{"v": a[len(a)-1]}, "v")
	}
	typ, value := jdType(str(d, "type"), false), str(d, "hostValue")
	if typ == "SRV" {
		value = str(d, "mxPriority") + " " + str(d, "weight") + " " + str(d, "port") + " " + value
	}
	return Record{ID: str(d, "id"), Name: str(d, "hostRecord"), Type: typ, Value: value, Line: line, TTL: integer(d, "ttl"), Priority: optionalInt(d, "mxPriority"), Weight: optionalInt(d, "weight"), Enabled: str(d, "resolvingStatus") == "2", Version: str(d, "updateTime")}
}
func (c *cloudAction) list(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	action := "ListRecords"
	p := map[string]any{"ZID": c.zoneID, "PageNumber": o.Page, "PageSize": o.PageSize, "SearchOrder": map[bool]string{true: "desc", false: "asc"}[o.Desc]}
	if c.kind == "huoshan" {
		if o.Name != "" || o.Type != "" || o.Line != "" || o.Value != "" {
			p["Host"], p["Type"], p["Line"], p["Value"], p["SearchMode"] = o.Name, o.Type, o.Line, o.Value, "exact"
		} else if o.Keyword != "" {
			p["Host"] = o.Keyword
		}
	} else {
		action = "/domain/" + pathID(c.zoneID) + "/ResourceRecord"
		p = map[string]any{"pageNumber": o.Page, "pageSize": min(o.PageSize, 99)}
		if o.Name != "" {
			p["search"] = o.Name
		} else if o.Keyword != "" {
			p["search"] = o.Keyword
		}
	}
	out, err := c.call(ctx, "GET", action, p)
	if err != nil {
		return RecordPage{}, err
	}
	key, total := "Records", integer(out, "TotalCount")
	if c.kind == "jdcloud" {
		key, total = "dataList", integer(out, "totalCount")
	}
	rows := []Record{}
	for _, d := range arr(out, key) {
		rows = append(rows, c.normalize(d))
	}
	return RecordPage{Total: total, Rows: rows}, nil
}
func (c *cloudAction) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	// JD search is fuzzy and does not support the normalized type/status filters. Fetch every page before client filtering.
	if c.kind == "jdcloud" && (o.Name != "" || o.Type != "" || o.Value != "" || o.Line != "" || o.Enabled != nil) || c.kind == "huoshan" && o.Enabled != nil {
		rows := []Record{}
		scan := o
		scan.PageSize = 99
		for scan.Page = 1; scan.Page <= 10000; scan.Page++ {
			page, err := c.list(ctx, scan)
			if err != nil {
				return RecordPage{}, err
			}
			rows = append(rows, page.Rows...)
			if len(page.Rows) == 0 || len(rows) >= page.Total {
				return recordPage(rows, o), nil
			}
		}
		return RecordPage{}, errors.New("record pagination limit exceeded")
	}
	return c.list(ctx, o)
}
func (c *cloudAction) GetRecord(ctx context.Context, id string) (Record, error) {
	if c.kind == "huoshan" {
		out, err := c.call(ctx, "GET", "QueryRecord", map[string]any{"RecordID": id})
		if err != nil {
			return Record{}, err
		}
		if str(out, "RecordID") == "" {
			return Record{}, ErrNotFound
		}
		return c.normalize(out), nil
	}
	count := 0
	for page := 1; page <= 10000; page++ {
		out, err := c.list(ctx, ListOptions{Page: page, PageSize: 99})
		if err != nil {
			return Record{}, err
		}
		for _, r := range out.Rows {
			if r.ID == id {
				return r, nil
			}
		}
		count += len(out.Rows)
		if len(out.Rows) == 0 || count >= out.Total {
			return Record{}, ErrNotFound
		}
	}
	return Record{}, errors.New("record pagination limit exceeded")
}
func (c *cloudAction) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := c.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	if id != "" && r.Version != "" {
		old, err := c.GetRecord(ctx, id)
		if err != nil {
			return Record{}, err
		}
		if old.Version != r.Version {
			return Record{}, ErrConflict
		}
	}
	name, err := asciiRecordName(r.Name, c.zoneName)
	if err != nil {
		return Record{}, err
	}
	name = relative(name, c.zoneName)
	action, method := "CreateRecord", "POST"
	p := map[string]any{}
	if c.kind == "huoshan" {
		p = map[string]any{"ZID": c.zoneID, "Host": name, "Type": r.Type, "Value": r.Value, "Line": r.Line, "TTL": r.TTL, "Remark": r.Remark}
		if p["Line"] == "" || p["Line"] == "0" {
			p["Line"] = "default"
		}
		if r.Type == "MX" {
			p["Value"] = strconv.Itoa(*r.Priority) + " " + r.Value
		}
		if r.Weight != nil {
			p["Weight"] = *r.Weight
		}
		if id != "" {
			action = "UpdateRecord"
			delete(p, "ZID")
			p["RecordID"] = id
		}
	} else {
		action = "/domain/" + pathID(c.zoneID) + "/ResourceRecord"
		line, err := strconv.Atoi(r.Line)
		if err != nil && r.Line != "" && r.Line != "default" {
			return Record{}, errors.New("JD line must be numeric")
		}
		req := map[string]any{"hostRecord": name, "type": jdType(r.Type, true), "hostValue": r.Value, "viewValue": line, "ttl": r.TTL}
		if r.Priority != nil {
			req["mxPriority"] = *r.Priority
		}
		if r.Weight != nil {
			req["weight"] = *r.Weight
		}
		if r.Type == "SRV" {
			parts := strings.SplitN(r.Value, " ", 4)
			if len(parts) != 4 {
				return Record{}, errors.New("SRV requires priority weight port target")
			}
			for i, k := range []string{"mxPriority", "weight", "port"} {
				n, err := strconv.Atoi(parts[i])
				if err != nil {
					return Record{}, err
				}
				req[k] = n
			}
			req["hostValue"] = parts[3]
		}
		if id != "" {
			method = "PUT"
			action += "/" + pathID(id)
			req["domainName"] = c.zoneName
		}
		p["req"] = req
	}
	out, err := c.call(ctx, method, action, p)
	if err != nil {
		return Record{}, err
	}
	if id == "" {
		if c.kind == "huoshan" {
			id = str(out, "RecordID")
		} else {
			id = str(obj(out, "dataList"), "id")
			if id == "" {
				id = str(obj(out, "data"), "id")
			}
		}
	}
	if id == "" {
		return Record{}, responseError(c.kind, 200, true, "provider omitted created record ID")
	}
	r.ID = id
	if err = c.SetStatus(ctx, id, r.Enabled); err != nil {
		return r, acceptedWriteError(c.kind, err)
	}
	return r, nil
}
func (c *cloudAction) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return c.write(ctx, "", r)
}
func (c *cloudAction) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return c.write(ctx, id, r)
}
func (c *cloudAction) DeleteRecord(ctx context.Context, id string) error {
	action, method, p := "DeleteRecord", "POST", map[string]any{"RecordID": id}
	if c.kind == "jdcloud" {
		method, action, p = "DELETE", "/domain/"+pathID(c.zoneID)+"/ResourceRecord/"+pathID(id), nil
	}
	_, err := c.call(ctx, method, action, p)
	return err
}
func (c *cloudAction) SetStatus(ctx context.Context, id string, on bool) error {
	action, method, p := "UpdateRecordStatus", "POST", map[string]any{"RecordID": id, "Enable": on}
	if c.kind == "jdcloud" {
		action, method, p = "/domain/"+pathID(c.zoneID)+"/ResourceRecord/"+pathID(id)+"/status", "PUT", map[string]any{"action": map[bool]string{true: "enable", false: "disable"}[on]}
	}
	_, err := c.call(ctx, method, action, p)
	return err
}
func (c *cloudAction) SetRemark(ctx context.Context, id, remark string) error {
	if c.kind != "huoshan" {
		return ErrCapability
	}
	r, err := c.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Remark = remark
	_, err = c.write(ctx, id, r)
	return err
}
func (c *cloudAction) zoneInfo(ctx context.Context) (map[string]any, error) {
	if c.kind == "huoshan" {
		return c.call(ctx, "GET", "QueryZone", map[string]any{"ZID": c.zoneID})
	}
	out, err := c.call(ctx, "GET", "/domain", map[string]any{"domainId": c.zoneID})
	if err != nil {
		return nil, err
	}
	for _, d := range arr(out, "dataList") {
		if str(d, "id") == c.zoneID {
			return d, nil
		}
	}
	return nil, ErrNotFound
}
func volcTrade(s string) (int, int) {
	switch s {
	case "professional_inner":
		return 2, 300
	case "enterprise_inner":
		return 3, 60
	case "ultimate_inner":
		return 4, 1
	case "ultimate_exclusive_inner":
		return 5, 1
	}
	return 1, 600
}
func (c *cloudAction) Lines(ctx context.Context) ([]Line, error) {
	info, err := c.zoneInfo(ctx)
	if err != nil {
		return nil, err
	}
	rows := []Line{}
	if c.kind == "huoshan" {
		level, _ := volcTrade(str(info, "TradeCode"))
		out, err := c.call(ctx, "GET", "ListLines", nil)
		if err != nil {
			return nil, err
		}
		rows = append(rows, Line{ID: "default", Name: "默认"})
		for _, l := range arr(out, "Lines") {
			if str(l, "Value") == "default" || integer(l, "Level") > level {
				continue
			}
			rows = append(rows, Line{ID: str(l, "Value"), Name: str(l, "Name"), Parent: str(l, "FatherValue")})
		}
		out, err = c.call(ctx, "GET", "ListCustomLines", nil)
		if err != nil {
			return nil, err
		}
		if integer(out, "TotalCount") > 0 {
			rows = append(rows, Line{ID: "N.customer_lines", Name: "自定义线路"})
			for _, l := range arr(out, "CustomerLines") {
				rows = append(rows, Line{ID: str(l, "Line"), Name: str(l, "NameCN"), Parent: "N.customer_lines"})
			}
		}
		return rows, nil
	}
	out, err := c.call(ctx, "GET", "/domain/"+pathID(c.zoneID)+"/viewTree", map[string]any{"packId": info["packId"], "viewId": "0"})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var visit func([]map[string]any, string)
	visit = func(ls []map[string]any, parent string) {
		for _, l := range ls {
			if boolean(l, "disabled") {
				continue
			}
			id := str(l, "value")
			if seen[id] {
				continue
			}
			seen[id] = true
			rows = append(rows, Line{ID: id, Name: str(l, "label"), Parent: parent})
			visit(arr(l, "children"), id)
		}
	}
	visit(arr(out, "data"), "")
	return rows, nil
}
func (c *cloudAction) MinTTL(ctx context.Context) (int, error) {
	if c.kind == "jdcloud" {
		return 1, nil
	}
	info, err := c.zoneInfo(ctx)
	if err != nil {
		return 0, err
	}
	_, ttl := volcTrade(str(info, "TradeCode"))
	return ttl, nil
}

var _ Provider = (*cloudAction)(nil)
