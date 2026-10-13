package dns

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type qingDNS struct{ *base }

func (q *qingDNS) call(ctx context.Context, method, path string, p map[string]any) (map[string]any, error) {
	date := q.now().UTC().Format(http.TimeFormat)
	query := url.Values{}
	var body any
	toSign := method + "\n" + date + "\n" + path
	if method == "GET" {
		query = queryValues(p)
		if len(query) > 0 {
			toSign += "?" + query.Encode()
		}
	} else {
		body = p
	}
	if q.cfg["access_key_id"] == "" || q.cfg["secret_access_key"] == "" {
		return nil, errors.New("Qingcloud access keys required")
	}
	h := http.Header{"Date": {date}, "Authorization": {"QC-HMAC-SHA256 " + q.cfg["access_key_id"] + ":" + base64.StdEncoding.EncodeToString(hmac256([]byte(q.cfg["secret_access_key"]), toSign))}}
	out, status, err := q.json(ctx, method, path, query, body, h)
	if err != nil {
		return nil, err
	}
	if code := str(out, "code"); code != "" && code != "0" {
		return nil, &RemoteError{Provider: q.kind, Status: status, Code: code, Message: firstString(out, "message", "msg")}
	}
	return out, nil
}
func (q *qingDNS) Validate(ctx context.Context) error {
	_, err := q.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (q *qingDNS) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	p := map[string]any{"offset": (o.Page - 1) * o.PageSize, "limit": o.PageSize}
	if o.Keyword != "" {
		p["zone_name"] = o.Keyword
	}
	out, err := q.call(ctx, "GET", "/v1/user/zones", p)
	if err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	for _, d := range arr(out, "zones") {
		rows = append(rows, Domain{ID: str(d, "zone_name"), Name: strings.TrimSuffix(str(d, "zone_name"), ".")})
	}
	return DomainPage{Total: integer(out, "total_count"), Rows: rows}, nil
}
func (q *qingDNS) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	out, err := q.call(ctx, "POST", "/v1/zone/", map[string]any{"zone_name": name})
	if err != nil {
		return Domain{}, err
	}
	return Domain{ID: str(out, "zone_name"), Name: name}, nil
}
func qingID(id string) (string, string, error) {
	a, b, ok := strings.Cut(id, "_")
	if !ok || a == "" || b == "" {
		return "", "", errors.New("Qingcloud ID must contain record and value IDs")
	}
	return a, b, nil
}
func (q *qingDNS) normalize(d map[string]any) []Record {
	rows := []Record{}
	for _, g := range arr(d, "record") {
		for _, v := range arr(g, "data") {
			value := str(v, "value")
			r := Record{ID: str(d, "domain_record_id") + "_" + str(v, "record_value_id"), Name: relative(str(d, "domain_name"), q.zoneName), Type: str(d, "rd_type"), Value: value, Line: str(d, "view_id"), TTL: integer(d, "ttl"), Enabled: integer(v, "status") == 1, Version: str(d, "create_time"), Metadata: jsonRaw(map[string]any{"mode": integer(d, "mode")})}
			if w := integer(g, "weight"); w > 0 {
				r.Weight = &w
			}
			if r.Type == "TXT" {
				r.Value = strings.Trim(value, "\"")
			}
			if r.Type == "MX" {
				parts := strings.SplitN(value, " ", 2)
				if len(parts) == 2 {
					n, _ := intValue(parts[0])
					r.Priority = &n
					r.Value = parts[1]
				}
			}
			rows = append(rows, r)
		}
	}
	return rows
}
func (q *qingDNS) host(ctx context.Context, name string) ([]Record, error) {
	out, err := q.call(ctx, "GET", "/v1/dns/host_info/", map[string]any{"zone_name": q.zoneID, "domain_name": absolute(name, q.zoneName) + "."})
	if err != nil {
		return nil, err
	}
	rows := []Record{}
	for _, d := range arr(out, "records") {
		rows = append(rows, q.normalize(d)...)
	}
	return rows, nil
}
func (q *qingDNS) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	if o.Name != "" {
		rows, err := q.host(ctx, o.Name)
		if err != nil {
			return RecordPage{}, err
		}
		return recordPage(rows, o), nil
	}
	rows := []Record{}
	count := 0
	for page := 0; page < 10000; page++ {
		out, err := q.call(ctx, "GET", "/v1/dns/host/", map[string]any{"zone_name": q.zoneID, "offset": page * 100, "limit": 100, "search_word": o.Keyword})
		if err != nil {
			return RecordPage{}, err
		}
		domains := arr(out, "domains")
		for _, d := range domains {
			hostRows, err := q.host(ctx, str(d, "domain_name"))
			if err != nil {
				return RecordPage{}, err
			}
			rows = append(rows, hostRows...)
		}
		count += len(domains)
		if len(domains) == 0 || count >= integer(out, "total_count") {
			return recordPage(rows, o), nil
		}
	}
	return RecordPage{}, errors.New("host pagination limit exceeded")
}
func (q *qingDNS) GetRecord(ctx context.Context, id string) (Record, error) {
	rid, _, err := qingID(id)
	if err != nil {
		return Record{}, err
	}
	out, err := q.call(ctx, "GET", "/v1/dr_id/"+pathID(rid), nil)
	if err != nil {
		return Record{}, err
	}
	for _, r := range q.normalize(obj(out, "data")) {
		if r.ID == id {
			return r, nil
		}
	}
	return Record{}, ErrNotFound
}
func qingValue(r Record) string {
	if r.Type == "MX" {
		return str(map[string]any{"v": *r.Priority}, "v") + " " + r.Value
	}
	if r.Type == "TXT" && !strings.HasPrefix(r.Value, "\"") {
		return "\"" + r.Value + "\""
	}
	return r.Value
}
func qingMode(r Record) int {
	m := map[string]any{}
	_ = json.Unmarshal(r.Metadata, &m)
	n := integer(m, "mode")
	if n < 1 || n > 3 {
		return 1
	}
	return n
}
func (q *qingDNS) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := q.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	mode := qingMode(r)
	weight := 0
	if r.Weight != nil && (r.Type == "A" || r.Type == "CNAME") && mode == 3 {
		weight = *r.Weight
	}
	groups := []map[string]any{}
	path := "/v1/record/"
	if id == "" {
		groups = append(groups, map[string]any{"weight": weight, "values": []map[string]any{{"value": qingValue(r), "status": map[bool]int{true: 1, false: 0}[r.Enabled]}}})
	} else {
		rid, vid, err := qingID(id)
		if err != nil {
			return Record{}, err
		}
		path = "/v1/dr_id/" + pathID(rid)
		out, err := q.call(ctx, "GET", path, nil)
		if err != nil {
			return Record{}, err
		}
		d := obj(out, "data")
		members := 0
		for _, group := range arr(d, "record") {
			members += len(arr(group, "data"))
		}
		targetLine := 0
		if r.Line != "" && r.Line != "default" {
			targetLine, _ = strconv.Atoi(r.Line)
		}
		if members > 1 && (relative(str(d, "domain_name"), q.zoneName) != r.Name || str(d, "rd_type") != r.Type || integer(d, "view_id") != targetLine) {
			return Record{}, errors.New("shared Qingcloud record group cannot change name, type or line through a single value")
		}
		if r.Version != "" && r.Version != str(d, "create_time") {
			return Record{}, ErrConflict
		}
		found := false
		for _, g := range arr(d, "record") {
			values := []map[string]any{}
			w := integer(g, "weight")
			for _, v := range arr(g, "data") {
				value, status := str(v, "value"), integer(v, "status")
				if str(v, "record_value_id") == vid {
					value, status = qingValue(r), map[bool]int{true: 1, false: 0}[r.Enabled]
					w = weight
					found = true
				}
				values = append(values, map[string]any{"value": value, "status": status})
			}
			if len(values) > 0 {
				groups = append(groups, map[string]any{"weight": w, "values": values})
			}
		}
		if !found {
			return Record{}, ErrNotFound
		}
	}
	encoded, _ := json.Marshal(groups)
	line, err := intValue(r.Line)
	if err != nil && r.Line != "" && r.Line != "default" {
		return Record{}, errors.New("Qingcloud line must be numeric")
	}
	p := map[string]any{"zone_name": q.zoneID, "domain_name": r.Name, "view_id": line, "type": r.Type, "ttl": r.TTL, "record": string(encoded), "mode": mode}
	if id == "" {
		p["auto_merge"] = 2
	}
	out, err := q.call(ctx, "POST", path, p)
	if err != nil {
		return Record{}, err
	}
	if id == "" {
		rid := str(out, "domain_record_id")
		out, err = q.call(ctx, "GET", "/v1/dr_id/"+pathID(rid), nil)
		if err != nil {
			return Record{}, acceptedWriteError(q.kind, err)
		}
		for _, row := range q.normalize(obj(out, "data")) {
			if row.Name == r.Name && row.Type == r.Type && row.Value == r.Value {
				r.ID = row.ID
				return r, nil
			}
		}
		return Record{}, responseError(q.kind, 200, true, "created value ID could not be reconciled")
	}
	r.ID = id
	return r, nil
}
func (q *qingDNS) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return q.write(ctx, "", r)
}
func (q *qingDNS) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return q.write(ctx, id, r)
}
func (q *qingDNS) DeleteRecord(ctx context.Context, id string) error {
	rid, vid, err := qingID(id)
	if err != nil {
		return err
	}
	path := "/v1/dr_id/" + pathID(rid)
	out, err := q.call(ctx, "GET", path, nil)
	if err != nil {
		return err
	}
	d := obj(out, "data")
	groups := []map[string]any{}
	found := false
	for _, g := range arr(d, "record") {
		values := []map[string]any{}
		for _, v := range arr(g, "data") {
			if str(v, "record_value_id") == vid {
				found = true
				continue
			}
			values = append(values, map[string]any{"value": str(v, "value"), "status": integer(v, "status")})
		}
		if len(values) > 0 {
			groups = append(groups, map[string]any{"weight": integer(g, "weight"), "values": values})
		}
	}
	if !found {
		return ErrNotFound
	}
	if len(groups) == 0 {
		encoded, _ := json.Marshal([]string{rid})
		_, err = q.call(ctx, "POST", "/v1/change_record_status/", map[string]any{"ids": string(encoded), "target": "record", "action": "delete"})
		return err
	}
	encoded, _ := json.Marshal(groups)
	_, err = q.call(ctx, "POST", path, map[string]any{"zone_name": q.zoneID, "domain_name": relative(str(d, "domain_name"), q.zoneName), "view_id": d["view_id"], "type": d["rd_type"], "ttl": d["ttl"], "record": string(encoded), "mode": d["mode"]})
	return err
}
func (q *qingDNS) SetStatus(ctx context.Context, id string, on bool) error {
	_, vid, err := qingID(id)
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal([]string{vid})
	_, err = q.call(ctx, "POST", "/v1/change_record_status/", map[string]any{"ids": string(encoded), "target": "value", "action": map[bool]string{true: "enable", false: "stop"}[on]})
	return err
}
func (q *qingDNS) Lines(ctx context.Context) ([]Line, error) {
	out, err := q.call(ctx, "GET", "/v1/zone/view/", map[string]any{"zone_name": q.zoneID, "type": "GET_FULL"})
	if err != nil {
		return nil, err
	}
	rows := []Line{}
	for _, l := range arr(out, "zone_views") {
		name := str(l, "name")
		if name == "*" {
			name = "默认"
		}
		rows = append(rows, Line{ID: str(l, "id"), Name: name})
	}
	return rows, nil
}
func (q *qingDNS) MinTTL(context.Context) (int, error) { return 60, nil }

var _ Provider = (*qingDNS)(nil)
