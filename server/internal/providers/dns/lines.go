package dns

import (
	"embed"
	"encoding/json"
	"sort"
)

//go:embed huawei_lines.json
var linesFS embed.FS

func huaweiLines() []Line {
	data, _ := linesFS.ReadFile("huawei_lines.json")
	var raw map[string]struct {
		Name   string  `json:"name"`
		Parent *string `json:"parent"`
	}
	_ = json.Unmarshal(data, &raw)
	rows := []Line{}
	for id, l := range raw {
		parent := ""
		if l.Parent != nil {
			parent = *l.Parent
		}
		rows = append(rows, Line{ID: id, Name: l.Name, Parent: parent})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows
}
