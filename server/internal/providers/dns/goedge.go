package dns

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type goEdge struct {
	*base
	mu    sync.Mutex
	token string
}

func (g *goEdge) call(ctx context.Context, path string, p map[string]any) (map[string]any, error) {
	g.mu.Lock()
	if g.token == "" {
		typ := g.cfg["type"]
		if typ == "" {
			typ = "admin"
		}
		out, _, err := g.json(ctx, "POST", "/APIAccessTokenService/getAPIAccessToken", nil, map[string]string{"type": typ, "accessKeyId": g.cfg["accessKeyId"], "accessKey": g.cfg["accessKey"]}, nil)
		if err != nil {
			g.mu.Unlock()
			return nil, classifyProtocolError(err, false)
		}
		if integer(out, "code") != 200 {
			g.mu.Unlock()
			return nil, &RemoteError{Provider: g.kind, Status: 200, Message: "GoEdge access token rejected"}
		}
		g.token = str(obj(out, "data"), "token")
		if g.token == "" {
			g.mu.Unlock()
			return nil, errors.New("GoEdge returned no access token")
		}
	}
	token := g.token
	g.mu.Unlock()
	if p == nil {
		p = map[string]any{}
	}
	out, status, err := g.json(ctx, "POST", path, nil, p, http.Header{"X-Edge-Access-Token": {token}})
	if err != nil {
		return nil, classifyProtocolError(err, !strings.Contains(path, "/find") && !strings.Contains(path, "/list") && !strings.Contains(path, "/count"))
	}
	if _, ok := out["code"]; !ok {
		return nil, responseError(g.kind, status, !strings.Contains(path, "/find") && !strings.Contains(path, "/list") && !strings.Contains(path, "/count"), "missing GoEdge result code")
	}
	if integer(out, "code") != 200 {
		return nil, &RemoteError{Provider: g.kind, Status: status, Code: str(out, "code"), Message: str(out, "message")}
	}
	return obj(out, "data"), nil
}
func (g *goEdge) domainQuery(keyword string) map[string]any {
	cluster, _ := strconv.Atoi(g.cfg["nsClusterId"])
	p := map[string]any{"nsClusterId": cluster}
	if keyword != "" {
		p["keyword"] = keyword
	}
	if g.cfg["type"] != "user" {
		if user, err := strconv.Atoi(g.cfg["userId"]); err == nil && user > 0 {
			p["userId"] = user
		}
	}
	return p
}
func (g *goEdge) Validate(ctx context.Context) error {
	cluster, _ := strconv.Atoi(g.cfg["nsClusterId"])
	if cluster < 1 {
		return errors.New("GoEdge DNS cluster ID must be positive")
	}
	out, err := g.call(ctx, "/NSClusterService/findNSCluster", map[string]any{"nsClusterId": cluster})
	if err != nil {
		return err
	}
	if len(obj(out, "nsCluster")) == 0 {
		return errors.New("GoEdge cluster not found")
	}
	return nil
}
func (g *goEdge) ListDomains(ctx context.Context, o ListOptions) (DomainPage, error) {
	o = normalizedOptions(o)
	query := g.domainQuery(o.Keyword)
	count, err := g.call(ctx, "/NSDomainService/countAllNSDomains", query)
	if err != nil {
		return DomainPage{}, err
	}
	query["offset"] = (o.Page - 1) * o.PageSize
	query["size"] = o.PageSize
	out, err := g.call(ctx, "/NSDomainService/listNSDomains", query)
	if err != nil {
		return DomainPage{}, err
	}
	rows := []Domain{}
	for _, z := range arr(out, "nsDomains") {
		rows = append(rows, Domain{ID: str(z, "id"), Name: str(z, "name")})
	}
	return DomainPage{Total: integer(count, "count"), Rows: rows}, nil
}
func (g *goEdge) CreateDomain(ctx context.Context, name string) (Domain, error) {
	name, err := CanonicalName(name)
	if err != nil {
		return Domain{}, err
	}
	p := g.domainQuery("")
	p["name"] = name
	out, err := g.call(ctx, "/NSDomainService/createNSDomain", p)
	if err != nil {
		return Domain{}, err
	}
	return Domain{ID: str(out, "nsDomainId"), Name: name}, nil
}
func (g *goEdge) normalize(m map[string]any) Record {
	codes := []string{}
	for _, r := range arr(m, "nsRoutes") {
		if code := str(r, "code"); code != "" {
			codes = append(codes, code)
		}
	}
	line := strings.Join(codes, ",")
	if line == "" {
		line = "default"
	}
	return Record{ID: str(m, "id"), Name: str(m, "name"), Type: str(m, "type"), Value: str(m, "value"), Line: line, TTL: integer(m, "ttl"), Priority: optionalInt(m, "mxPriority"), Weight: optionalInt(m, "weight"), Remark: str(m, "description"), Enabled: boolean(m, "isOn"), Metadata: jsonRaw(m)}
}
func (g *goEdge) ListRecords(ctx context.Context, o ListOptions) (RecordPage, error) {
	rows := []Record{}
	id, err := strconv.Atoi(g.zoneID)
	if err != nil {
		return RecordPage{}, errors.New("invalid GoEdge zone ID")
	}
	for page := 0; page < 1000; page++ {
		out, err := g.call(ctx, "/NSRecordService/listNSRecords", map[string]any{"nsDomainId": id, "offset": page * 1000, "size": 1000})
		if err != nil {
			return RecordPage{}, err
		}
		records := arr(out, "nsRecords")
		for _, r := range records {
			rows = append(rows, g.normalize(r))
		}
		if len(records) < 1000 {
			return recordPage(rows, o), nil
		}
	}
	return RecordPage{}, errors.New("GoEdge pagination limit exceeded")
}
func (g *goEdge) GetRecord(ctx context.Context, id string) (Record, error) {
	n, err := strconv.Atoi(id)
	if err != nil {
		return Record{}, err
	}
	out, err := g.call(ctx, "/NSRecordService/findNSRecord", map[string]any{"nsRecordId": n})
	if err != nil {
		return Record{}, err
	}
	r := obj(out, "nsRecord")
	if len(r) == 0 {
		return Record{}, ErrNotFound
	}
	return g.normalize(r), nil
}
func (g *goEdge) write(ctx context.Context, id string, r Record) (Record, error) {
	if prepared, err := g.prepare(r); err != nil {
		return Record{}, err
	} else {
		r = prepared
	}
	zone, err := strconv.Atoi(g.zoneID)
	if err != nil {
		return Record{}, err
	}
	codes := []string{}
	for _, c := range strings.Split(r.Line, ",") {
		if c = strings.TrimSpace(c); c != "" {
			codes = append(codes, c)
		}
	}
	if len(codes) == 0 {
		codes = []string{"default"}
	}
	p := map[string]any{"nsDomainId": zone, "isOn": r.Enabled, "name": r.Name, "type": r.Type, "value": r.Value, "ttl": r.TTL, "nsRouteCodes": codes, "description": r.Remark, "weight": 0, "mxPriority": 0}
	if r.Weight != nil {
		p["weight"] = *r.Weight
	}
	if r.Priority != nil {
		p["mxPriority"] = *r.Priority
	}
	action := "/NSRecordService/createNSRecord"
	if id != "" {
		n, err := strconv.Atoi(id)
		if err != nil {
			return Record{}, err
		}
		action = "/NSRecordService/updateNSRecord"
		p["nsRecordId"] = n
	}
	out, err := g.call(ctx, action, p)
	if err != nil {
		return Record{}, err
	}
	if id == "" {
		id = str(out, "nsRecordId")
	}
	if id == "" {
		return Record{}, responseError(g.kind, 200, true, "GoEdge omitted created record ID")
	}
	r.ID = id
	return r, nil
}
func (g *goEdge) CreateRecord(ctx context.Context, r Record) (Record, error) {
	return g.write(ctx, "", r)
}
func (g *goEdge) UpdateRecord(ctx context.Context, id string, r Record) (Record, error) {
	return g.write(ctx, id, r)
}
func (g *goEdge) DeleteRecord(ctx context.Context, id string) error {
	n, err := strconv.Atoi(id)
	if err != nil {
		return err
	}
	_, err = g.call(ctx, "/NSRecordService/deleteNSRecord", map[string]any{"nsRecordId": n})
	return err
}
func (g *goEdge) SetStatus(ctx context.Context, id string, enabled bool) error {
	r, err := g.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Enabled = enabled
	_, err = g.UpdateRecord(ctx, id, r)
	return err
}
func (g *goEdge) SetRemark(ctx context.Context, id, remark string) error {
	r, err := g.GetRecord(ctx, id)
	if err != nil {
		return err
	}
	r.Remark = remark
	_, err = g.UpdateRecord(ctx, id, r)
	return err
}
func (g *goEdge) Lines(ctx context.Context) ([]Line, error) {
	seen := map[string]Line{"default": {ID: "default", Name: "默认线路"}}
	methods := []string{"/NSRouteService/findAllNSRoutes", "/NSRouteService/findAllPublicNSRoutes"}
	for _, method := range methods {
		out, err := g.call(ctx, method, map[string]any{})
		if err != nil {
			return nil, err
		}
		for _, r := range arr(out, "nsRoutes") {
			code := str(r, "code")
			if code != "" {
				seen[code] = Line{ID: code, Name: firstString(r, "name", "code"), Parent: str(r, "parent")}
			}
		}
	}
	rows := []Line{seen["default"]}
	delete(seen, "default")
	for code, l := range seen {
		if l.Parent == "" {
			if i := strings.LastIndex(code, ":"); i > 0 {
				if _, ok := seen[code[:i]]; ok {
					l.Parent = code[:i]
				}
			}
		}
		rows = append(rows, l)
	}
	return rows, nil
}

var _ Provider = (*goEdge)(nil)
