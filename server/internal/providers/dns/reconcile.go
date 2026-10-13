package dns

import (
	"context"
	"errors"
	"slices"
)

// DesiredEqual compares the complete public DNS tuple, including RRsets and
// optional priorities. Provider-generated IDs and version metadata are excluded.
func DesiredEqual(a, b Record) bool {
	line := func(v string) string {
		if v == "" {
			return "default"
		}
		return v
	}
	values := func(r Record) []string {
		v := slices.Clone(r.Values)
		if len(v) == 0 {
			v = []string{r.Value}
		}
		slices.Sort(v)
		return slices.Compact(v)
	}
	number := func(v *int) int {
		if v == nil {
			return 0
		}
		return *v
	}
	return a.Name == b.Name && a.Type == b.Type && slices.Equal(values(a), values(b)) && line(a.Line) == line(b.Line) && a.TTL == b.TTL && a.Enabled == b.Enabled && a.Proxied == b.Proxied && number(a.Priority) == number(b.Priority) && number(a.Weight) == number(b.Weight) && a.Remark == b.Remark
}

// ObserveMutation never writes. Exactly one complete matching record is needed
// to confirm a create/update whose provider ID may change with its value.
func ObserveMutation(ctx context.Context, p Provider, operation string, desired Record) (Record, bool, error) {
	if operation != "create" {
		current, err := p.GetRecord(ctx, desired.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return Record{}, false, err
		}
		switch operation {
		case "delete":
			return current, errors.Is(err, ErrNotFound), nil
		case "enable", "disable":
			return current, err == nil && current.Enabled == (operation == "enable"), nil
		case "remark":
			return current, err == nil && current.Remark == desired.Remark, nil
		case "update":
			if err == nil && DesiredEqual(current, desired) {
				return current, true, nil
			}
			if err == nil {
				return current, false, nil
			} // An old tuple still exists; a new match alone cannot confirm a rename.
		default:
			return Record{}, false, errors.New("unknown DNS mutation")
		}
	}
	var found Record
	matches := 0
	for page := 1; page <= 100; page++ {
		rows, err := p.ListRecords(ctx, ListOptions{Name: desired.Name, Type: desired.Type, Page: page, PageSize: 100})
		if err != nil {
			return Record{}, false, err
		}
		for _, r := range rows.Rows {
			if DesiredEqual(r, desired) {
				matches++
				found = r
			}
		}
		if len(rows.Rows) < 100 || (rows.Total > 0 && page*100 >= rows.Total) {
			return found, matches == 1, nil
		}
	}
	return Record{}, false, errors.New("record scan limit exceeded")
}
