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

type powerDNS struct {
	*base
	serverID string
}
type pdRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}
type pdComment struct {
	Account string `json:"account"`
	Content string `json:"content"`
}
type pdSet struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	TTL      int         `json:"ttl,omitempty"`
	Records  []pdRecord  `json:"records,omitempty"`
	Comments []pdComment `json:"comments,omitempty"`
	Change   string      `json:"changetype,omitempty"`
}

func newPowerDNS(b *base) (Provider, error) {
	if b.endpoint == "" {
		if b.cfg["url"] != "" {
			b.endpoint = strings.TrimSuffix(b.cfg["url"], "/")
		} else {
			b.endpoint = "http://" + b.cfg["ip"] + ":" + b.cfg["port"] + "/api/v1"
		}
	}
	server := b.cfg["server_id"]
	if server == "" {
		server = "localhost"
	}
	return &powerDNS{base: b, serverID: server}, nil
}
func (p *powerDNS) path(zone bool) string {
	s := "/servers/" + pathID(p.serverID) + "/zones"
	if zone {
		s += "/" + pathID(p.zoneID)
	}
	return s
}
func (p *powerDNS) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	if p.cfg["apikey"] == "" {
		return nil, errors.New("PowerDNS API key required")
	}
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	raw, status, err := p.raw(ctx, method, path, nil, encoded, http.Header{"X-API-Key": {p.cfg["apikey"]}, "Content-Type": {"application/json"}})
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		var payload map[string]any
		_ = json.Unmarshal(raw, &payload)
		return nil, &RemoteError{Provider: p.kind, Status: status, Message: firstString(payload, "error", "message"), UnknownResult: status >= 500 && methodWrites(method)}
	}
	if len(raw) > 0 {
		var decoded any
		if err := decodeJSON(raw, &decoded); err != nil || decoded == nil {
			return nil, responseError(p.kind, status, methodWrites(method), "invalid PowerDNS JSON response")
		}
	}
	return raw, nil
}
func (p *powerDNS) Validate(ctx context.Context) error {
	_, err := p.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (p *powerDNS) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	raw, err := p.request(ctx, "GET", p.path(false), nil)
	if err != nil {
		return DomainPage{}, err
	}
	var zs []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err = json.Unmarshal(raw, &zs); err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	for _, z := range zs {
		rows = append(rows, Domain{ID: z.ID, Name: strings.TrimSuffix(z.Name, ".")})
	}
	return domainPage(rows, o), nil
}
func (p *powerDNS) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	raw, err := p.request(ctx, "POST", p.path(false), map[string]any{"name": name + ".", "kind": "Native", "soa_edit_api": "INCREASE"})
	if err != nil {
		return Domain{}, err
	}
	var z Domain
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		return Domain{}, err
	}
	z.ID = str(m, "id")
	z.Name = strings.TrimSuffix(str(m, "name"), ".")
	return z, nil
}
func (p *powerDNS) sets(ctx context.Context) ([]pdSet, error) {
	raw, err := p.request(ctx, "GET", p.path(true), nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Sets []pdSet `json:"rrsets"`
	}
	if err = json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal(raw, &envelope)
	if _, ok := envelope["rrsets"]; !ok {
		return nil, responseError(p.kind, 200, false, "missing PowerDNS RRsets response")
	}
	return payload.Sets, nil
}
func setID(name, typ, content string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name + "\x1e" + typ + "\x1e" + content))
}
func splitID(id string) (string, string, string, error) {
	data, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", "", "", ErrNotFound
	}
	parts := strings.SplitN(string(data), "\x1e", 3)
	if len(parts) != 3 {
		return "", "", "", ErrNotFound
	}
	return parts[0], parts[1], parts[2], nil
}
func parseContent(typ, value string) (string, *int) {
	if typ == "MX" {
		parts := strings.SplitN(value, " ", 2)
		if len(parts) == 2 {
			n, _ := strconv.Atoi(parts[0])
			return strings.TrimSuffix(parts[1], "."), &n
		}
	}
	if typ == "TXT" && strings.HasPrefix(value, "\"") && !strings.Contains(value, "\" \"") {
		if decoded, err := strconv.Unquote(value); err == nil {
			return decoded, nil
		}
	}
	if typ == "CNAME" || typ == "NS" || typ == "PTR" {
		return strings.TrimSuffix(value, "."), nil
	}
	return value, nil
}
func formatContent(r Record) (string, error) {
	value := r.Value
	typ := strings.ToUpper(r.Type)
	if typ == "TXT" || typ == "SPF" {
		if !strings.HasPrefix(value, "\"") {
			value = strconv.Quote(value)
		}
	}
	if typ == "CNAME" || typ == "NS" || typ == "PTR" || typ == "MX" {
		var err error
		value, err = CanonicalName(value)
		if err != nil {
			return "", err
		}
		value += "."
	}
	if typ == "MX" {
		value = strconv.Itoa(*r.Priority) + " " + value
	}
	return value, nil
}
func (p *powerDNS) normalize(set pdSet, record pdRecord) Record {
	value, mx := parseContent(set.Type, record.Content)
	remark := ""
	if len(set.Comments) > 0 {
		remark = set.Comments[0].Content
	}
	return Record{ID: setID(set.Name, set.Type, record.Content), Name: relative(set.Name, p.zoneName), Type: set.Type, Value: value, Line: "default", TTL: set.TTL, Priority: mx, Remark: remark, Enabled: !record.Disabled, Metadata: jsonRaw(map[string]any{"rrset_name": set.Name, "raw_value": record.Content})}
}
func (p *powerDNS) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	sets, err := p.sets(ctx)
	if err != nil {
		return RecordPage{}, err
	}
	rows := []Record{}
	for _, set := range sets {
		for _, record := range set.Records {
			rows = append(rows, p.normalize(set, record))
		}
	}
	return recordPage(rows, o), nil
}
func (p *powerDNS) GetRecord(ctx context.Context, id string) (Record, error) {
	name, typ, value, err := splitID(id)
	if err != nil {
		return Record{}, err
	}
	sets, err := p.sets(ctx)
	if err != nil {
		return Record{}, err
	}
	for _, set := range sets {
		if set.Name == name && set.Type == typ {
			for _, record := range set.Records {
				if record.Content == value {
					return p.normalize(set, record), nil
				}
			}
		}
	}
	return Record{}, ErrNotFound
}
func (p *powerDNS) patch(ctx context.Context, sets []pdSet) error {
	_, err := p.request(ctx, "PATCH", p.path(true), map[string]any{"rrsets": sets})
	return err
}
func replaceSet(set pdSet) pdSet {
	if len(set.Records) == 0 {
		return pdSet{Name: set.Name, Type: set.Type, Change: "DELETE"}
	}
	set.Change = "REPLACE"
	return set
}
func (p *powerDNS) CreateRecord(ctx context.Context, r Record) (Record, error) {
	if prepared, err := p.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	name, err := asciiRecordName(r.Name, p.zoneName)
	if err != nil {
		return Record{}, err
	}
	name += "."
	typ := strings.ToUpper(r.Type)
	if typ == "SPF" {
		typ = "TXT"
	}
	content, err := formatContent(r)
	if err != nil {
		return Record{}, err
	}
	sets, err := p.sets(ctx)
	if err != nil {
		return Record{}, err
	}
	target := pdSet{Name: name, Type: typ, TTL: r.TTL, Records: []pdRecord{}, Comments: []pdComment{}}
	for _, set := range sets {
		if set.Name == name && set.Type == typ {
			target = set
			for _, existing := range set.Records {
				if existing.Content == content {
					return Record{}, errors.New("identical record already exists")
				}
			}
			break
		}
	}
	target.TTL = r.TTL
	target.Records = append(target.Records, pdRecord{Content: content, Disabled: !r.Enabled})
	if r.Remark != "" {
		target.Comments = []pdComment{{Content: r.Remark}}
	}
	if err = p.patch(ctx, []pdSet{replaceSet(target)}); err != nil {
		return Record{}, err
	}
	return p.normalize(target, pdRecord{Content: content, Disabled: !r.Enabled}), nil
}
func (p *powerDNS) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := p.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	oldName, oldType, oldValue, err := splitID(id)
	if err != nil {
		return Record{}, err
	}
	name, err := asciiRecordName(r.Name, p.zoneName)
	if err != nil {
		return Record{}, err
	}
	name += "."
	typ := strings.ToUpper(r.Type)
	if typ == "SPF" {
		typ = "TXT"
	}
	content, err := formatContent(r)
	if err != nil {
		return Record{}, err
	}
	sets, err := p.sets(ctx)
	if err != nil {
		return Record{}, err
	}
	oldIndex, newIndex, recordIndex := -1, -1, -1
	for i, set := range sets {
		if set.Name == oldName && set.Type == oldType {
			oldIndex = i
			for j, record := range set.Records {
				if record.Content == oldValue {
					recordIndex = j
				}
			}
		}
		if set.Name == name && set.Type == typ {
			newIndex = i
		}
	}
	if oldIndex < 0 || recordIndex < 0 {
		return Record{}, ErrNotFound
	}
	if oldName == name && oldType == typ {
		set := sets[oldIndex]
		for i, existing := range set.Records {
			if i != recordIndex && existing.Content == content {
				return Record{}, errors.New("identical record already exists")
			}
		}
		set.TTL = r.TTL
		set.Records[recordIndex] = pdRecord{Content: content, Disabled: !r.Enabled}
		set.Comments = []pdComment{}
		if r.Remark != "" {
			set.Comments = []pdComment{{Content: r.Remark}}
		}
		if err = p.patch(ctx, []pdSet{replaceSet(set)}); err != nil {
			return Record{}, err
		}
		return p.normalize(set, set.Records[recordIndex]), nil
	}
	old := sets[oldIndex]
	old.Records = append(old.Records[:recordIndex], old.Records[recordIndex+1:]...)
	target := pdSet{Name: name, Type: typ, TTL: r.TTL}
	if newIndex >= 0 {
		target = sets[newIndex]
		for _, existing := range target.Records {
			if existing.Content == content {
				return Record{}, errors.New("identical record already exists")
			}
		}
	}
	target.TTL = r.TTL
	target.Records = append(target.Records, pdRecord{Content: content, Disabled: !r.Enabled})
	if r.Remark != "" {
		target.Comments = []pdComment{{Content: r.Remark}}
	}
	if err = p.patch(ctx, []pdSet{replaceSet(old), replaceSet(target)}); err != nil {
		return Record{}, err
	}
	return p.normalize(target, pdRecord{Content: content, Disabled: !r.Enabled}), nil
}
func (p *powerDNS) DeleteRecord(ctx context.Context, id string) error {
	name, typ, value, err := splitID(id)
	if err != nil {
		return err
	}
	sets, err := p.sets(ctx)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if set.Name == name && set.Type == typ {
			for i, r := range set.Records {
				if r.Content == value {
					set.Records = append(set.Records[:i], set.Records[i+1:]...)
					return p.patch(ctx, []pdSet{replaceSet(set)})
				}
			}
		}
	}
	return ErrNotFound
}
func (p *powerDNS) SetStatus(ctx context.Context, id string, enabled bool) error {
	r, err := p.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Enabled = enabled
	_, err = p.UpdateRecord(ctx, id, r)
	return err
}
func (p *powerDNS) SetRemark(ctx context.Context, id, remark string) error {
	r, err := p.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Remark = remark
	_, err = p.UpdateRecord(ctx, id, r)
	return err
}

var _ Provider = (*powerDNS)(nil)
var _ = url.Values{}
