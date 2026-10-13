package dns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type restProvider struct{ *base }

func (x *restProvider) request(ctx context.Context, method, path string, q url.Values, body any) (any, error) {
	headers := http.Header{}
	switch x.kind {
	case "dynv6":
		if x.cfg["token"] == "" {
			return nil, errors.New("dynv6 token required")
		}
		headers.Set("Authorization", "Bearer "+x.cfg["token"])
	case "spaceship":
		headers.Set("X-API-Key", x.cfg["apikey"])
		headers.Set("X-API-Secret", x.cfg["apisecret"])
	case "dnsla":
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(x.cfg["apiid"]+":"+x.cfg["apisecret"])))
	}
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
		headers.Set("Content-Type", "application/json")
	}
	raw, status, err := x.raw(ctx, method, path, q, encoded, headers)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 && status >= 200 && status < 300 {
		return map[string]any{}, nil
	}
	var data any
	if err = decodeJSON(raw, &data); err != nil || data == nil {
		return nil, responseError(x.kind, status, methodWrites(method), "invalid JSON response")
	}
	if status >= 400 {
		m, _ := data.(map[string]any)
		return nil, &RemoteError{Provider: x.kind, Status: status, Message: firstString(m, "detail", "message", "error", "msg"), UnknownResult: status >= 500 && method != "GET" && method != "HEAD"}
	}
	if x.kind == "dnsla" {
		m, _ := data.(map[string]any)
		if integer(m, "code") != 200 {
			return nil, &RemoteError{Provider: x.kind, Status: status, Code: str(m, "code"), Message: str(m, "msg")}
		}
		return m["data"], nil
	}
	return data, nil
}
func mapData(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func listData(v any) []map[string]any {
	if m, ok := v.(map[string]any); ok {
		if m["id"] != nil {
			return []map[string]any{m}
		}
	}
	a, _ := v.([]any)
	out := []map[string]any{}
	for _, item := range a {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
func (x *restProvider) Validate(ctx context.Context) error {
	_, err := x.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (x *restProvider) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	path := "/zones"
	q := url.Values{}
	if x.kind == "spaceship" {
		path = "/domains"
		q.Set("take", strconv.Itoa(o.PageSize))
		q.Set("skip", strconv.Itoa((o.Page-1)*o.PageSize))
	}
	if x.kind == "dnsla" {
		path = "/api/domainList"
		q.Set("pageIndex", strconv.Itoa(o.Page))
		q.Set("pageSize", strconv.Itoa(o.PageSize))
	}
	data, err := x.request(ctx, "GET", path, q, nil)
	if err != nil {
		return DomainPage{}, err
	}
	raw := listData(data)
	total := len(raw)
	if x.kind == "spaceship" {
		raw = arr(mapData(data), "items")
		total = integer(mapData(data), "total")
	}
	if x.kind == "dnsla" {
		raw = arr(mapData(data), "results")
		total = integer(mapData(data), "total")
	}
	rows := []Domain{}
	for _, d := range raw {
		switch x.kind {
		case "spaceship":
			rows = append(rows, Domain{ID: str(d, "name"), Name: str(d, "name")})
		case "dnsla":
			rows = append(rows, Domain{ID: str(d, "id"), Name: strings.TrimSuffix(str(d, "displayDomain"), ".")})
		default:
			rows = append(rows, Domain{ID: str(d, "id"), Name: str(d, "name")})
		}
	}
	if x.kind == "dynv6" {
		return domainPage(rows, o), nil
	}
	return DomainPage{Total: total, Rows: rows}, nil
}
func (x *restProvider) zone(ctx context.Context) (string, error) {
	if x.zoneID != "" {
		return x.zoneID, nil
	}
	for page := 1; page < 1000; page++ {
		ds, err := x.ListDomains(ctx, ListOptions{Page: page, PageSize: 100})
		if err != nil {
			return "", err
		}
		for _, d := range ds.Rows {
			if strings.EqualFold(d.Name, x.zoneName) {
				return d.ID, nil
			}
		}
		if page*100 >= ds.Total {
			break
		}
	}
	return "", errors.New("provider zone not found")
}

var dnsTypes = map[int]string{1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA", 256: "FORWARD_URL"}

func dnsTypeNumber(typ string) int {
	if typ == "REDIRECT_URL" || typ == "FORWARD_URL" {
		return 256
	}
	for n, v := range dnsTypes {
		if v == typ {
			return n
		}
	}
	return 0
}
func (x *restProvider) normalize(m map[string]any) Record {
	if x.kind == "dynv6" {
		return Record{ID: str(m, "id"), Name: relative(str(m, "name"), x.zoneName), Type: strings.ToUpper(str(m, "type")), Value: str(m, "data"), TTL: 600, Line: "default", Priority: optionalInt(m, "priority"), Enabled: true}
	}
	if x.kind == "dnsla" {
		typ := dnsTypes[integer(m, "type")]
		if integer(m, "type") == 256 && (boolean(m, "dominant") || boolean(m, "domaint")) {
			typ = "REDIRECT_URL"
		}
		return Record{ID: str(m, "id"), Name: str(m, "host"), Type: typ, Value: str(m, "data"), Line: str(m, "lineId"), TTL: integer(m, "ttl"), Priority: optionalInt(m, "preference"), Weight: optionalInt(m, "weight"), Enabled: !boolean(m, "disable"), Version: str(m, "updatedAt")}
	}
	typ := str(m, "type")
	value := ""
	var mx *int
	switch typ {
	case "MX":
		value = str(m, "exchange")
		mx = optionalInt(m, "preference")
	case "CNAME":
		value = str(m, "cname")
	case "TXT":
		value = str(m, "value")
	case "PTR":
		value = str(m, "pointer")
	case "NS":
		value = str(m, "nameserver")
	case "CAA":
		value = fmt.Sprintf("%d %s %s", integer(m, "flag"), str(m, "tag"), str(m, "value"))
	case "SRV":
		value = fmt.Sprintf("%d %d %d %s", integer(m, "priority"), integer(m, "weight"), integer(m, "port"), str(m, "target"))
	case "ALIAS":
		value = str(m, "aliasName")
	default:
		value = str(m, "address")
	}
	r := Record{Name: str(m, "name"), Type: typ, Value: value, TTL: integer(m, "ttl"), Line: "default", Priority: mx, Enabled: true, Metadata: jsonRaw(m)}
	r.ID = setID(r.Name, r.Type, value)
	return r
}
func (x *restProvider) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	path := ""
	q := url.Values{}
	switch x.kind {
	case "dynv6":
		zone, err := x.zone(ctx)
		if err != nil {
			return RecordPage{}, err
		}
		path = "/zones/" + pathID(zone) + "/records"
	case "spaceship":
		path = "/dns/records/" + pathID(x.zoneName)
		q.Set("take", strconv.Itoa(o.PageSize))
		q.Set("skip", strconv.Itoa((o.Page-1)*o.PageSize))
	case "dnsla":
		path = "/api/recordList"
		q.Set("domainId", x.zoneID)
		q.Set("pageIndex", strconv.Itoa(o.Page))
		q.Set("pageSize", strconv.Itoa(o.PageSize))
		host := o.Keyword
		if o.Name != "" {
			host = o.Name
		}
		if host != "" {
			q.Set("host", host)
		}
		if o.Type != "" {
			q.Set("type", strconv.Itoa(dnsTypeNumber(o.Type)))
		}
		if o.Line != "" {
			q.Set("lineId", o.Line)
		}
		if o.Value != "" {
			q.Set("data", o.Value)
		}
	}
	data, err := x.request(ctx, "GET", path, q, nil)
	if err != nil {
		return RecordPage{}, err
	}
	raw := listData(data)
	total := len(raw)
	if x.kind == "spaceship" {
		raw = arr(mapData(data), "items")
		total = integer(mapData(data), "total")
	}
	if x.kind == "dnsla" {
		raw = arr(mapData(data), "results")
		total = integer(mapData(data), "total")
	}
	rows := []Record{}
	for _, m := range raw {
		rows = append(rows, x.normalize(m))
	}
	if x.kind == "dynv6" {
		return recordPage(rows, o), nil
	}
	return RecordPage{Total: total, Rows: rows}, nil
}
func (x *restProvider) GetRecord(ctx context.Context, id string) (Record, error) {
	if x.kind == "spaceship" {
		parts := strings.SplitN(id, "|", 4)
		if len(parts) == 4 {
			id = setID(parts[1], parts[0], parts[2])
		}
	}
	for page := 1; page < 1000; page++ {
		list, err := x.ListRecords(ctx, ListOptions{Page: page, PageSize: 100})
		if err != nil {
			return Record{}, err
		}
		for _, r := range list.Rows {
			if r.ID == id {
				return r, nil
			}
		}
		if page*100 >= list.Total {
			break
		}
	}
	return Record{}, ErrNotFound
}
func spaceshipItem(r Record) (map[string]any, error) {
	m := map[string]any{"name": r.Name, "type": r.Type}
	switch r.Type {
	case "MX":
		m["exchange"] = r.Value
		m["preference"] = *r.Priority
	case "CNAME":
		m["cname"] = r.Value
	case "TXT":
		m["value"] = r.Value
	case "PTR":
		m["pointer"] = r.Value
	case "NS":
		m["nameserver"] = r.Value
	case "ALIAS":
		m["aliasName"] = r.Value
	case "CAA":
		p := strings.SplitN(r.Value, " ", 3)
		if len(p) != 3 {
			return nil, errors.New("CAA requires flag tag value")
		}
		n, err := strconv.Atoi(p[0])
		if err != nil {
			return nil, err
		}
		m["flag"] = n
		m["tag"] = p[1]
		m["value"] = strings.Trim(p[2], "\"")
	case "SRV":
		p := strings.Fields(r.Value)
		if len(p) != 4 {
			return nil, errors.New("SRV requires priority weight port target")
		}
		for i, k := range []string{"priority", "weight", "port"} {
			n, err := strconv.Atoi(p[i])
			if err != nil {
				return nil, err
			}
			m[k] = n
		}
		m["target"] = p[3]
	default:
		m["address"] = r.Value
	}
	return m, nil
}
func (x *restProvider) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := x.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	switch x.kind {
	case "dynv6":
		zone, err := x.zone(ctx)
		if err != nil {
			return Record{}, err
		}
		name := r.Name
		if name == "@" {
			name = x.zoneName
		}
		value := r.Value
		if (r.Type == "CNAME" || r.Type == "MX") && strings.Contains(value, ".") {
			value = strings.TrimSuffix(value, ".") + "."
		}
		m := map[string]any{"name": name, "type": r.Type, "data": value}
		if r.Type == "MX" {
			m["priority"] = *r.Priority
		}
		method, path := "POST", "/zones/"+pathID(zone)+"/records"
		if id != "" {
			method = "PATCH"
			path += "/" + pathID(id)
		}
		data, err := x.request(ctx, method, path, nil, m)
		if err != nil {
			return Record{}, err
		}
		if got := str(mapData(data), "id"); got != "" {
			id = got
		}
		if id == "" {
			return r, responseError(x.kind, 200, true, "provider omitted created record ID")
		}
		r.ID = id
		return r, nil
	case "dnsla":
		n := dnsTypeNumber(r.Type)
		if n == 0 {
			return Record{}, errors.New("DNSLA does not support this type")
		}
		m := map[string]any{"domainId": x.zoneID, "type": n, "host": r.Name, "data": r.Value, "ttl": r.TTL, "lineId": r.Line}
		if r.Type == "MX" {
			m["preference"] = *r.Priority
		}
		if n == 256 {
			m["dominant"] = r.Type == "REDIRECT_URL"
		}
		if r.Weight != nil {
			m["weight"] = *r.Weight
		}
		method := "POST"
		if id != "" {
			method = "PUT"
			m["id"] = id
			delete(m, "domainId")
		}
		data, err := x.request(ctx, method, "/api/record", nil, m)
		if err != nil {
			return Record{}, err
		}
		if id == "" {
			id = str(mapData(data), "id")
		}
		if id == "" {
			return r, responseError(x.kind, 200, true, "DNSLA omitted created record ID")
		}
		r.ID = id
		if id != "" || !r.Enabled {
			if err = x.SetStatus(ctx, id, r.Enabled); err != nil {
				return r, acceptedWriteError(x.kind, err)
			}
		}
		return r, nil
	case "spaceship":
		if !r.Enabled {
			return Record{}, ErrCapability
		}
		item, err := spaceshipItem(r)
		if err != nil {
			return Record{}, err
		}
		item["ttl"] = r.TTL
		items := []any{item}
		force := false
		var old *Record
		if id != "" {
			current, err := x.GetRecord(ctx, id)
			if err != nil {
				return Record{}, err
			}
			old = &current
			if current.Name == r.Name && current.Type == r.Type {
				force = true
				for page := 1; page <= 10000; page++ {
					set, err := x.ListRecords(ctx, ListOptions{Page: page, PageSize: 100})
					if err != nil {
						return Record{}, err
					}
					for _, sibling := range set.Rows {
						if sibling.Name == current.Name && sibling.Type == current.Type && sibling.ID != id {
							keep, err := spaceshipItem(sibling)
							if err != nil {
								return Record{}, err
							}
							keep["ttl"] = r.TTL
							items = append(items, keep)
						}
					}
					if len(set.Rows) == 0 || page*100 >= set.Total {
						break
					}
					if page == 10000 {
						return Record{}, errors.New("record pagination limit exceeded")
					}
				}
			}
		}
		_, err = x.request(ctx, "PUT", "/dns/records/"+pathID(x.zoneName), nil, map[string]any{"force": force, "items": items})
		if err != nil {
			return Record{}, err
		}
		r.ID = setID(r.Name, r.Type, r.Value)
		if old != nil && (old.Name != r.Name || old.Type != r.Type) {
			oldItem, err := spaceshipItem(*old)
			if err != nil {
				return r, err
			}
			if _, err = x.request(ctx, "DELETE", "/dns/records/"+pathID(x.zoneName), nil, []any{oldItem}); err != nil {
				return r, &PartialWriteError{Provider: x.kind, RecordID: r.ID, Message: "new record exists; old record could not be removed", Cause: err}
			}
		}
		return r, nil
	}
	return Record{}, errors.New("unknown REST provider")
}
func (x *restProvider) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return x.write(ctx, "", r)
}
func (x *restProvider) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return x.write(ctx, id, r)
}
func (x *restProvider) DeleteRecord(ctx context.Context, id string) error {
	switch x.kind {
	case "dynv6":
		zone, err := x.zone(ctx)
		if err != nil {
			return err
		}
		_, err = x.request(ctx, "DELETE", "/zones/"+pathID(zone)+"/records/"+pathID(id), nil, nil)
		return err
	case "dnsla":
		_, err := x.request(ctx, "DELETE", "/api/record", url.Values{"id": {id}}, nil)
		return err
	case "spaceship":
		old, err := x.GetRecord(ctx, id)
		if err != nil {
			return err
		}
		item, err := spaceshipItem(old)
		if err != nil {
			return err
		}
		_, err = x.request(ctx, "DELETE", "/dns/records/"+pathID(x.zoneName), nil, []any{item})
		return err
	}
	return ErrCapability
}
func (x *restProvider) SetStatus(ctx context.Context, id string, enabled bool) error {
	if x.kind != "dnsla" {
		return ErrCapability
	}
	_, err := x.request(ctx, "PUT", "/api/recordDisable", nil, map[string]any{"id": id, "disable": !enabled})
	return err
}
func (x *restProvider) CreateDomain(ctx context.Context, name string) (Domain, error) {
	if x.kind != "dnsla" {
		return Domain{}, ErrCapability
	}
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	data, err := x.request(ctx, "POST", "/api/domain", nil, map[string]string{"domain": name})
	if err != nil {
		return Domain{}, err
	}
	return Domain{ID: str(mapData(data), "id"), Name: name}, nil
}
func (x *restProvider) Lines(ctx context.Context) ([]Line, error) {
	if x.kind != "dnsla" {
		return x.base.Lines(ctx)
	}
	data, err := x.request(ctx, "GET", "/api/availableLine", url.Values{"domain": {x.zoneName}}, nil)
	if err != nil {
		return nil, err
	}
	rows := []Line{}
	for _, m := range listData(data) {
		rows = append(rows, Line{ID: str(m, "id"), Name: str(m, "value"), Parent: str(m, "pid")})
	}
	return rows, nil
}
func (x *restProvider) MinTTL(ctx context.Context) (int, error) {
	if x.kind != "dnsla" {
		if x.kind == "dynv6" {
			return 600, nil
		}
		return 1, nil
	}
	data, err := x.request(ctx, "GET", "/api/dnsMeasures", url.Values{"id": {x.zoneID}}, nil)
	if err != nil {
		return 0, err
	}
	return integer(mapData(data), "minTTL"), nil
}

var _ Provider = (*restProvider)(nil)
