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

type technitium struct{ *base }

func (t *technitium) call(ctx context.Context, method, path string, p url.Values) (map[string]any, error) {
	if p == nil {
		p = url.Values{}
	}
	p.Set("token", t.cfg["token"])
	q := url.Values{}
	var body []byte
	if method == "GET" {
		q = p
	} else {
		body = []byte(p.Encode())
	}
	raw, status, err := t.raw(ctx, method, path, q, body, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err = decodeJSON(raw, &out); err != nil || out == nil {
		return nil, responseError(t.kind, status, methodWrites(method), "invalid Technitium JSON response")
	}
	if _, ok := out["status"]; !ok {
		return nil, responseError(t.kind, status, methodWrites(method), "missing Technitium result status")
	}
	if status >= 400 || str(out, "status") != "ok" {
		return nil, &RemoteError{Provider: t.kind, Status: status, Message: firstString(out, "errorMessage", "message"), UnknownResult: status >= 500 && methodWrites(method)}
	}
	return obj(out, "response"), nil
}
func (t *technitium) Validate(ctx context.Context) error {
	_, err := t.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (t *technitium) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	out, err := t.call(ctx, "GET", "/zones/list", nil)
	if err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	for _, z := range arr(out, "zones") {
		rows = append(rows, Domain{ID: str(z, "name"), Name: str(z, "name")})
	}
	return domainPage(rows, o), nil
}
func (t *technitium) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	out, err := t.call(ctx, "POST", "/zones/create", url.Values{"zone": {name}, "type": {"Primary"}})
	if err != nil {
		return Domain{}, err
	}
	return Domain{ID: str(out, "domain"), Name: str(out, "domain")}, nil
}
func techData(typ string, d map[string]any) (string, *int) {
	switch typ {
	case "A", "AAAA":
		return str(d, "ipAddress"), nil
	case "CNAME":
		return str(d, "cname"), nil
	case "NS":
		return str(d, "nameServer"), nil
	case "MX":
		return str(d, "exchange"), optionalInt(d, "preference")
	case "TXT":
		return str(d, "text"), nil
	case "PTR":
		return str(d, "ptrName"), nil
	case "ANAME":
		return str(d, "aname"), nil
	case "DNAME":
		return str(d, "dname"), nil
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", integer(d, "priority"), integer(d, "weight"), integer(d, "port"), str(d, "target")), nil
	case "CAA":
		return fmt.Sprintf("%d %s %s", integer(d, "flags"), str(d, "tag"), str(d, "value")), nil
	case "APP":
		return strings.TrimSpace(str(d, "appName") + " " + str(d, "classPath") + " " + str(d, "recordData")), nil
	default:
		return firstString(d, "value", "text"), nil
	}
}
func (t *technitium) normalize(m map[string]any) Record {
	value, mx := techData(str(m, "type"), obj(m, "rData"))
	name := relative(str(m, "name"), t.zoneName)
	return Record{ID: setID(name, str(m, "type"), value), Name: name, Type: str(m, "type"), Value: value, TTL: integer(m, "ttl"), Priority: mx, Line: "default", Enabled: !boolean(m, "disabled"), Remark: str(m, "comments"), Metadata: jsonRaw(m)}
}
func (t *technitium) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	out, err := t.call(ctx, "GET", "/zones/records/get", url.Values{"domain": {t.zoneName}, "listZone": {"true"}})
	if err != nil {
		return RecordPage{}, err
	}
	rows := []Record{}
	for _, m := range arr(out, "records") {
		rows = append(rows, t.normalize(m))
	}
	return recordPage(rows, o), nil
}
func (t *technitium) GetRecord(ctx context.Context, id string) (Record, error) {
	out, err := t.ListRecords(ctx, ListOptions{PageSize: 1000})
	if err != nil {
		return Record{}, err
	}
	for _, r := range out.Rows {
		if r.ID == id {
			return r, nil
		}
	}
	return Record{}, ErrNotFound
}
func techParams(r Record, newValue bool) (url.Values, error) {
	p := url.Values{}
	keys := map[string]string{"A": "ipAddress", "AAAA": "ipAddress", "CNAME": "cname", "NS": "nameServer", "MX": "exchange", "TXT": "text", "PTR": "ptrName", "ANAME": "aname", "DNAME": "dname"}
	newKeys := map[string]string{"A": "newIpAddress", "AAAA": "newIpAddress", "CNAME": "newCname", "NS": "newNameServer", "MX": "newExchange", "TXT": "newText", "PTR": "newPtrName", "ANAME": "newAName", "DNAME": "newDName"}
	if key := keys[r.Type]; key != "" {
		if newValue {
			key = newKeys[r.Type]
		}
		p.Set(key, r.Value)
		if r.Type == "MX" {
			k := "preference"
			if newValue {
				k = "newPreference"
			}
			p.Set(k, strconv.Itoa(*r.Priority))
		}
		return p, nil
	}
	switch r.Type {
	case "SRV":
		fields := strings.Fields(r.Value)
		if len(fields) != 4 {
			return nil, errors.New("SRV requires priority weight port target")
		}
		for i, k := range []string{"priority", "weight", "port", "target"} {
			if newValue {
				k = "new" + strings.ToUpper(k[:1]) + k[1:]
			}
			p.Set(k, fields[i])
		}
	case "CAA":
		fields := strings.SplitN(r.Value, " ", 3)
		if len(fields) != 3 {
			return nil, errors.New("CAA requires flags tag value")
		}
		for i, k := range []string{"flags", "tag", "value"} {
			if newValue {
				k = "new" + strings.ToUpper(k[:1]) + k[1:]
			}
			p.Set(k, strings.Trim(fields[i], "\""))
		}
	case "APP":
		fields := strings.SplitN(r.Value, " ", 3)
		for i, k := range []string{"appName", "classPath", "recordData"} {
			if i < len(fields) {
				p.Set(k, fields[i])
			}
		}
	default:
		var m map[string]any
		if err := json.Unmarshal(r.Metadata, &m); err != nil {
			return nil, errors.New("record type requires original metadata")
		}
		for k, v := range obj(m, "rData") {
			p.Set(k, fmt.Sprint(v))
		}
	}
	return p, nil
}
func mergeForm(to, from url.Values) {
	for k, v := range from {
		to[k] = v
	}
}
func (t *technitium) CreateRecord(ctx context.Context, r Record) (Record, error) {
	if prepared, err := t.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	p, err := techParams(r, false)
	if err != nil {
		return Record{}, err
	}
	name, err := asciiRecordName(r.Name, t.zoneName)
	if err != nil {
		return Record{}, err
	}
	p.Set("domain", name)
	p.Set("zone", t.zoneName)
	p.Set("type", r.Type)
	p.Set("ttl", strconv.Itoa(r.TTL))
	p.Set("comments", r.Remark)
	_, err = t.call(ctx, "POST", "/zones/records/add", p)
	if err != nil {
		return Record{}, err
	}
	r.ID = setID(r.Name, r.Type, r.Value)
	if !r.Enabled {
		err = t.SetStatus(ctx, r.ID, false)
	}
	return r, acceptedWriteError(t.kind, err)
}
func (t *technitium) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := t.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	old, err := t.GetRecord(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if old.Type != r.Type {
		return Record{}, errors.New("Technitium type change requires explicit delete and create")
	}
	p, err := techParams(old, false)
	if err != nil {
		return Record{}, err
	}
	newValues, err := techParams(r, true)
	if err != nil {
		return Record{}, err
	}
	mergeForm(p, newValues)
	p.Set("domain", absolute(old.Name, t.zoneName))
	p.Set("newDomain", absolute(r.Name, t.zoneName))
	p.Set("zone", t.zoneName)
	p.Set("type", old.Type)
	p.Set("ttl", strconv.Itoa(r.TTL))
	p.Set("comments", r.Remark)
	p.Set("disable", strconv.FormatBool(!r.Enabled))
	_, err = t.call(ctx, "POST", "/zones/records/update", p)
	r.ID = setID(r.Name, r.Type, r.Value)
	return r, err
}
func (t *technitium) recordAction(ctx context.Context, id, action string, changes url.Values) error {
	old, err := t.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	p, err := techParams(old, false)
	if err != nil {
		return err
	}
	p.Set("domain", absolute(old.Name, t.zoneName))
	p.Set("zone", t.zoneName)
	p.Set("type", old.Type)
	mergeForm(p, changes)
	_, err = t.call(ctx, "POST", "/zones/records/"+action, p)
	return err
}
func (t *technitium) DeleteRecord(ctx context.Context, id string) error {
	return t.recordAction(ctx, id, "delete", nil)
}
func (t *technitium) SetStatus(ctx context.Context, id string, enabled bool) error {
	return t.recordAction(ctx, id, "update", url.Values{"disable": {strconv.FormatBool(!enabled)}})
}
func (t *technitium) SetRemark(ctx context.Context, id, remark string) error {
	return t.recordAction(ctx, id, "update", url.Values{"comments": {remark}})
}

var _ Provider = (*technitium)(nil)
