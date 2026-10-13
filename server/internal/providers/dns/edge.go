package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type edgeDNS struct{ *base }

func (e *edgeDNS) call(ctx context.Context, action string, p map[string]any) (map[string]any, error) {
	return (&rpcProvider{base: e.base}).call(ctx, action, p)
}
func (e *edgeDNS) Validate(ctx context.Context) error {
	_, err := e.ListDomains(ctx, ListOptions{PageSize: 1})
	return err
}
func (e *edgeDNS) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	p := map[string]any{}
	action := "ListSites"
	if e.kind == "aliyunesa" {
		p = map[string]any{"SiteName": o.Keyword, "PageNumber": o.Page, "PageSize": o.PageSize, "AccessType": "NS"}
	} else {
		action = "DescribeZones"
		filters := []map[string]any{{"Name": "zone-type", "Values": []string{"full"}}}
		if o.Keyword != "" {
			filters = append(filters, map[string]any{"Name": "zone-name", "Values": []string{o.Keyword}})
		}
		p = map[string]any{"Offset": (o.Page - 1) * o.PageSize, "Limit": o.PageSize, "Filters": filters}
	}
	out, err := e.call(ctx, action, p)
	if err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	if e.kind == "aliyunesa" {
		for _, d := range arr(out, "Sites") {
			rows = append(rows, Domain{ID: str(d, "SiteId"), Name: str(d, "SiteName")})
		}
	} else {
		for _, d := range arr(out, "Zones") {
			rows = append(rows, Domain{ID: str(d, "ZoneId"), Name: str(d, "ZoneName")})
		}
	}
	return DomainPage{Total: integer(out, "TotalCount"), Rows: rows}, nil
}
func (e *edgeDNS) normalize(d map[string]any) Record {
	if e.kind == "tencenteo" {
		r := Record{ID: str(d, "RecordId"), Name: relative(str(d, "Name"), e.zoneName), Type: str(d, "Type"), Value: str(d, "Content"), Line: str(d, "Location"), TTL: integer(d, "TTL"), Priority: optionalInt(d, "Priority"), Weight: optionalInt(d, "Weight"), Enabled: str(d, "Status") == "enable", Version: str(d, "ModifiedOn")}
		if r.Weight != nil && *r.Weight < 0 {
			r.Weight = nil
		}
		return r
	}
	data := obj(d, "Data")
	typ, value := str(d, "RecordType"), str(data, "Value")
	switch typ {
	case "CAA":
		value = str(data, "Flag") + " " + str(data, "Tag") + " " + value
	case "SRV":
		value = str(data, "Priority") + " " + str(data, "Weight") + " " + str(data, "Port") + " " + value
	case "A/AAAA":
		if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
			typ = "AAAA"
		} else {
			typ = "A"
		}
	}
	proxied := boolean(d, "Proxied")
	return Record{ID: str(d, "RecordId"), Name: relative(str(d, "RecordName"), e.zoneName), Type: typ, Value: value, Line: map[bool]string{true: "1", false: "0"}[proxied], TTL: integer(d, "Ttl"), Priority: optionalInt(data, "Priority"), Remark: str(d, "Comment"), Enabled: true, Proxied: proxied, Version: str(d, "UpdateTime")}
}
func (e *edgeDNS) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	o = normalizedOptions(o)
	p := map[string]any{}
	action := "ListRecords"
	if e.kind == "aliyunesa" {
		p = map[string]any{"SiteId": e.zoneID, "PageNumber": o.Page, "PageSize": o.PageSize}
		name := o.Name
		if name == "" {
			name = o.Keyword
		}
		if name != "" {
			p["RecordName"] = absolute(name, e.zoneName)
		}
		if o.Type != "" {
			typ := o.Type
			if typ == "A" || typ == "AAAA" {
				typ = "A/AAAA"
			}
			p["Type"] = typ
		}
		if o.Line != "" {
			p["Proxied"] = o.Line == "1"
		}
	} else {
		action = "DescribeDnsRecords"
		filters := []map[string]any{}
		name := o.Name
		if name == "" {
			name = o.Keyword
		}
		if name != "" {
			filters = append(filters, map[string]any{"Name": "name", "Values": []string{absolute(name, e.zoneName)}})
		}
		if o.Value != "" {
			filters = append(filters, map[string]any{"Name": "content", "Values": []string{o.Value}, "Fuzzy": false})
		}
		if o.Type != "" {
			filters = append(filters, map[string]any{"Name": "type", "Values": []string{o.Type}})
		}
		p = map[string]any{"ZoneId": e.zoneID, "Offset": (o.Page - 1) * o.PageSize, "Limit": o.PageSize, "Filters": filters}
		if s := map[string]string{"Name": "name", "Type": "type", "Value": "content", "UpdateTime": "modified-on"}[o.Sort]; s != "" {
			p["SortBy"] = s
			p["SortOrder"] = map[bool]string{true: "desc", false: "asc"}[o.Desc]
		}
	}
	out, err := e.call(ctx, action, p)
	if err != nil {
		return RecordPage{}, err
	}
	key := "Records"
	if e.kind == "tencenteo" {
		key = "DnsRecords"
	}
	rows := []Record{}
	for _, d := range arr(out, key) {
		rows = append(rows, e.normalize(d))
	}
	return RecordPage{Total: integer(out, "TotalCount"), Rows: rows}, nil
}
func (e *edgeDNS) GetRecord(ctx context.Context, id string) (Record, error) {
	if e.kind == "aliyunesa" {
		out, err := e.call(ctx, "GetRecord", map[string]any{"RecordId": id})
		if err != nil {
			return Record{}, err
		}
		d := obj(out, "RecordModel")
		if len(d) == 0 {
			return Record{}, ErrNotFound
		}
		return e.normalize(d), nil
	}
	out, err := e.call(ctx, "DescribeDnsRecords", map[string]any{"ZoneId": e.zoneID, "Filters": []map[string]any{{"Name": "id", "Values": []string{id}}}})
	if err != nil {
		return Record{}, err
	}
	for _, d := range arr(out, "DnsRecords") {
		if str(d, "RecordId") == id {
			return e.normalize(d), nil
		}
	}
	return Record{}, ErrNotFound
}
func (e *edgeDNS) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := e.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	name, err := asciiRecordName(r.Name, e.zoneName)
	if err != nil {
		return Record{}, err
	}
	if id != "" && r.Version != "" {
		old, err := e.GetRecord(ctx, id)
		if err != nil {
			return Record{}, err
		}
		if old.Version != r.Version {
			return Record{}, ErrConflict
		}
	}
	action := "CreateRecord"
	p := map[string]any{}
	if e.kind == "aliyunesa" {
		if !r.Enabled {
			return Record{}, ErrCapability
		}
		typ := r.Type
		if typ == "A" || typ == "AAAA" {
			typ = "A/AAAA"
		}
		data := map[string]any{"Value": r.Value}
		parts := strings.SplitN(r.Value, " ", 4)
		switch r.Type {
		case "CAA":
			parts = strings.SplitN(r.Value, " ", 3)
			if len(parts) != 3 {
				return Record{}, errors.New("CAA requires flag tag value")
			}
			n, err := strconv.Atoi(parts[0])
			if err != nil {
				return Record{}, err
			}
			data = map[string]any{"Flag": n, "Tag": parts[1], "Value": parts[2]}
		case "SRV":
			if len(parts) != 4 {
				return Record{}, errors.New("SRV requires priority weight port target")
			}
			data = map[string]any{"Value": parts[3]}
			for i, k := range []string{"Priority", "Weight", "Port"} {
				n, err := strconv.Atoi(parts[i])
				if err != nil {
					return Record{}, err
				}
				data[k] = n
			}
		case "MX":
			data["Priority"] = *r.Priority
		}
		encoded, _ := json.Marshal(data)
		proxied := r.Proxied || r.Line == "1"
		p = map[string]any{"SiteId": e.zoneID, "RecordName": name, "Type": typ, "Proxied": proxied, "Ttl": r.TTL, "Data": string(encoded), "Comment": r.Remark}
		if proxied {
			p["BizName"] = "web"
		}
		if id != "" {
			action = "UpdateRecord"
			p["RecordId"] = id
			delete(p, "SiteId")
			delete(p, "RecordName")
		}
	} else {
		action = "CreateDnsRecord"
		weight := -1
		if r.Weight != nil {
			weight = *r.Weight
		}
		line := r.Line
		if line == "" || line == "0" || line == "default" {
			line = "Default"
		}
		p = map[string]any{"ZoneId": e.zoneID, "Name": name, "Type": r.Type, "Content": r.Value, "Location": line, "TTL": r.TTL, "Weight": weight}
		if r.Type == "MX" {
			p["Priority"] = *r.Priority
		}
		if id != "" {
			action = "ModifyDnsRecord"
			p["DnsRecordId"] = id
		}
	}
	out, err := e.call(ctx, action, p)
	if err != nil {
		return Record{}, err
	}
	if writtenID := str(out, "RecordId"); writtenID != "" {
		id = writtenID
	}
	if id == "" {
		return Record{}, responseError(e.kind, 200, true, "provider omitted created record ID")
	}
	r.ID = id
	if e.kind == "tencenteo" {
		if err = e.SetStatus(ctx, id, r.Enabled); err != nil {
			return r, acceptedWriteError(e.kind, err)
		}
	}
	return r, nil
}
func (e *edgeDNS) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return e.write(ctx, "", r)
}
func (e *edgeDNS) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	if e.kind == "aliyunesa" {
		old, err := e.GetRecord(ctx, id)
		if err != nil {
			return Record{}, err
		}
		if !strings.EqualFold(old.Name, r.Name) {
			return Record{}, fmt.Errorf("ESA does not support renaming an existing record")
		}
	}
	return e.write(ctx, id, r)
}
func (e *edgeDNS) DeleteRecord(ctx context.Context, id string) error {
	action := "DeleteRecord"
	p := map[string]any{"RecordId": id}
	if e.kind == "tencenteo" {
		action = "DeleteDnsRecords"
		p = map[string]any{"ZoneId": e.zoneID, "RecordIds": []string{id}}
	}
	_, err := e.call(ctx, action, p)
	return err
}
func (e *edgeDNS) SetStatus(ctx context.Context, id string, enabled bool) error {
	if e.kind != "tencenteo" {
		return ErrCapability
	}
	key := "RecordsToDisable"
	if enabled {
		key = "RecordsToEnable"
	}
	_, err := e.call(ctx, "ModifyDnsRecordsStatus", map[string]any{"ZoneId": e.zoneID, key: []string{id}})
	return err
}
func (e *edgeDNS) SetRemark(ctx context.Context, id, remark string) error {
	if e.kind != "aliyunesa" {
		return ErrCapability
	}
	r, err := e.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Remark = remark
	_, err = e.write(ctx, id, r)
	return err
}
func (e *edgeDNS) Lines(context.Context) ([]Line, error) {
	if e.kind == "aliyunesa" {
		return []Line{{ID: "0", Name: "仅DNS"}, {ID: "1", Name: "已代理"}}, nil
	}
	return []Line{{ID: "Default", Name: "默认"}}, nil
}
func (e *edgeDNS) MinTTL(context.Context) (int, error) {
	if e.kind == "tencenteo" {
		return 60, nil
	}
	return 1, nil
}

var _ Provider = (*edgeDNS)(nil)
