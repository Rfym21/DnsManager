package httpapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/shakinm/xlsReader/cfb"
	"github.com/shakinm/xlsReader/xls"
	"github.com/xuri/excelize/v2"
)

const importMaxBytes = 2 << 20
const importMaxRows = 5000
const importMaxColumns = 64

type importNotice struct {
	Row     int    `json:"row"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
type importItem struct {
	dns.Record
	SourceRow    int    `json:"source_row"`
	LineName     string `json:"line_name"`
	LineFallback bool   `json:"line_fallback"`
	Valid        bool   `json:"valid"`
}
type importPreview struct {
	Items    []importItem   `json:"items"`
	Issues   []importNotice `json:"issues"`
	Warnings []importNotice `json:"warnings"`
	Source   map[string]any `json:"source"`
}

// recordImportPreview only reads provider capabilities. A separate batch request
// must authorize every domain again before any external record change is queued.
func (a *API) recordImportPreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importMaxBytes+(64<<10))
	if err := r.ParseMultipartForm(importMaxBytes); err != nil {
		a.fail(w, r, 400, "invalid_import", "请选择不超过 2MB 的 Excel 文件")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	id := r.FormValue("domain_id")
	if id == "" {
		a.fail(w, r, 400, "invalid_import", "请先选择一个管理域名")
		return
	}
	if !a.authorizeDomain(w, r, id, "dns:read") {
		return
	}
	domain, err := a.Store.Domain(r.Context(), id)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	account, err := a.Store.Account(r.Context(), domain.AccountID)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	provider, err := a.DNSFactory(account.Provider, account.Config, domain.ProviderDomainID, domain.ASCIIName)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		a.fail(w, r, 400, "invalid_import", "缺少 Excel 文件")
		return
	}
	defer file.Close()
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".xlsx" && ext != ".xls" {
		a.fail(w, r, 400, "invalid_import", "仅支持 .xls 和 .xlsx 文件")
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, importMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > importMaxBytes {
		a.fail(w, r, 400, "invalid_import", "Excel 文件为空或超过 2MB")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rows, sheet, err := readImportWorkbook(ctx, data, ext)
	if err != nil {
		a.fail(w, r, 400, "invalid_import", err.Error())
		return
	}
	lines, err := provider.Lines(ctx)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	minTTL, err := provider.MinTTL(ctx)
	if err != nil {
		a.providerError(w, r, err)
		return
	}
	preview, err := normalizeImportRows(rows, lines, minTTL, domain.ASCIIName, provider.Descriptor().Capabilities)
	if err != nil {
		a.fail(w, r, 400, "invalid_import", err.Error())
		return
	}
	preview.Source = map[string]any{"filename": filepath.Base(header.Filename), "sheet": sheet, "domain_id": domain.ID, "domain_name": domain.Name, "rows": len(rows) - 1, "max_rows": importMaxRows}
	send(w, 200, preview)
}

// Legacy BIFF libraries are protected by a byte/read budget and panic recovery.
// No formula, macro, hyperlink, or external workbook reference is executed.
func readImportWorkbook(ctx context.Context, data []byte, ext string) (rows [][]string, sheet string, err error) {
	defer func() {
		if recover() != nil {
			rows, sheet, err = nil, "", errors.New("Excel 格式损坏，请重新导出")
		}
	}()
	if ext == ".xlsx" {
		book, e := excelize.OpenReader(bytes.NewReader(data), excelize.Options{UnzipSizeLimit: 20 << 20, UnzipXMLSizeLimit: 5 << 20})
		if e != nil {
			return nil, "", errors.New("无法读取 XLSX 文件，请检查文件格式")
		}
		defer book.Close()
		names := book.GetSheetList()
		if len(names) == 0 {
			return nil, "", errors.New("Excel 没有工作表")
		}
		sheet = names[0]
		iter, e := book.Rows(sheet)
		if e != nil {
			return nil, "", errors.New("无法读取首个工作表")
		}
		defer iter.Close()
		for iter.Next() {
			if e := ctx.Err(); e != nil {
				return nil, "", e
			}
			if len(rows) > importMaxRows {
				return nil, "", errors.New("首个工作表最多 5000 条数据行")
			}
			cells, e := iter.Columns()
			if e != nil || len(cells) > importMaxColumns {
				return nil, "", errors.New("工作表读取失败或超过 64 列")
			}
			rows = append(rows, cells)
		}
		if iter.Error() != nil {
			return nil, "", errors.New("工作表数据损坏")
		}
	} else {
		reader := &importReadBudget{Reader: bytes.NewReader(data), ctx: ctx, remaining: 64 << 20}
		compound, e := cfb.OpenReader(reader)
		if e != nil {
			return nil, "", errors.New("无法读取 XLS 文件，请检查文件格式")
		}
		var workbook, root *cfb.Directory
		for _, dir := range compound.GetDirs() {
			if binary.LittleEndian.Uint64(dir.StreamSize[:]) > importMaxBytes {
				return nil, "", errors.New("XLS 数据流超过大小限制")
			}
			if dir.Name() == "Workbook" || dir.Name() == "Book" {
				workbook = dir
			}
			if dir.Name() == "Root Entry" {
				root = dir
			}
		}
		if workbook == nil || root == nil {
			return nil, "", errors.New("XLS 没有工作表数据")
		}
		stream, e := compound.OpenObject(workbook, root)
		if e != nil {
			return nil, "", errors.New("XLS 工作表数据损坏")
		}
		biff, e := io.ReadAll(io.LimitReader(stream, importMaxBytes+1))
		if e != nil || len(biff) > importMaxBytes {
			return nil, "", errors.New("XLS 数据超过大小限制")
		}
		// Reject malformed records and formulas rather than importing missing or
		// cached results as if they were literal DNS values.
		for offset := 0; offset+4 <= int(workbook.GetStreamSize()); {
			if offset+4 > len(biff) {
				return nil, "", errors.New("XLS 数据被截断")
			}
			kind, size := binary.LittleEndian.Uint16(biff[offset:]), int(binary.LittleEndian.Uint16(biff[offset+2:]))
			if offset+4+size > len(biff) {
				return nil, "", errors.New("XLS 数据被截断")
			}
			if kind == 0x06 {
				return nil, "", errors.New("XLS 包含公式，请先将公式粘贴为值后导入")
			}
			offset += 4 + size
		}
		reader = &importReadBudget{Reader: bytes.NewReader(data), ctx: ctx, remaining: 64 << 20}
		book, e := xls.OpenReader(reader)
		if e != nil || book.GetNumberSheets() == 0 {
			return nil, "", errors.New("XLS 没有可读取的工作表")
		}
		s, e := book.GetSheet(0)
		if e != nil || s.GetNumberRows() > importMaxRows+1 {
			return nil, "", errors.New("首个工作表最多 5000 条数据行")
		}
		sheet = s.GetName()
		for _, row := range s.GetRows() {
			if e := ctx.Err(); e != nil {
				return nil, "", e
			}
			cols := row.GetCols()
			if len(cols) > importMaxColumns {
				return nil, "", errors.New("工作表最多 64 列")
			}
			cells := make([]string, len(cols))
			for i, cell := range cols {
				cells[i] = cell.GetString()
			}
			rows = append(rows, cells)
		}
	}
	if len(rows) < 2 {
		return nil, "", errors.New("首个工作表没有可导入的数据")
	}
	return rows, sheet, nil
}

type importReadBudget struct {
	*bytes.Reader
	ctx       context.Context
	remaining int
}

func (r *importReadBudget) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > r.remaining {
		return 0, errors.New("XLS 读取超过安全限制")
	}
	r.remaining -= len(p)
	return r.Reader.Read(p)
}

var importMXValue = regexp.MustCompile(`^(.*?)\s+\|\s+(\d+)$`)
var importCarrier = regexp.MustCompile(`中国(移动|联通|电信|教育网|广电|铁通|鹏博士|科技网)`)
var importRegion = regexp.MustCompile(`(东北|华东|华中|华南|西北|西南)地区`)

func normalizeImportRows(rows [][]string, lines []dns.Line, minTTL int, zone string, caps dns.Capabilities) (importPreview, error) {
	p := importPreview{Items: []importItem{}, Issues: []importNotice{}, Warnings: []importNotice{}}
	columns := map[string]int{}
	aliases := map[string]string{"主机记录": "name", "主机名": "name", "name": "name", "记录类型": "type", "类型": "type", "type": "type", "线路类型": "line", "线路": "line", "linename": "line", "line": "line", "记录值": "value", "value": "value", "ttl": "ttl", "权重": "weight", "weight": "weight", "备注": "remark", "remark": "remark", "优先级": "priority", "mx": "priority", "priority": "priority"}
	for i, header := range rows[0] {
		if key := aliases[strings.ToLower(strings.TrimSpace(header))]; key != "" {
			if _, duplicate := columns[key]; duplicate {
				return p, fmt.Errorf("重复字段：%s", header)
			}
			columns[key] = i
		}
	}
	for _, key := range []string{"name", "type", "value"} {
		if _, found := columns[key]; !found {
			return p, errors.New("首行须包含主机记录/Name、记录类型/Type、记录值/Value 字段")
		}
	}
	if minTTL < 1 {
		minTTL = 1
	}
	defaultLine := dns.Line{ID: "default", Name: "默认"}
	if len(lines) > 0 {
		defaultLine = lines[0]
	}
	byLine := map[string]dns.Line{}
	for _, line := range lines {
		byLine[line.ID] = line
		canonical := canonicalImportLine(line.Name)
		if _, exists := byLine[canonical]; !exists {
			byLine[canonical] = line
		}
		if canonical == "默认" {
			defaultLine = line
		}
	}
	for i, row := range rows[1:] {
		rowNum := i + 2
		column := func(key string) string {
			index, ok := columns[key]
			if !ok || index >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[index])
		}
		name, kind, value := column("name"), strings.ToUpper(column("type")), column("value")
		if name == "" && kind == "" && value == "" {
			continue
		}
		if (kind == "NS" || kind == "SOA") && (name == "@" || strings.EqualFold(strings.TrimSuffix(name, "."), zone)) {
			p.Warnings = append(p.Warnings, importNotice{rowNum, "root_authority_skipped", "已跳过根域名 NS/SOA 权威记录"})
			continue
		}
		if kind == "显性URL" {
			kind = "REDIRECT_URL"
		}
		if kind == "隐性URL" {
			kind = "FORWARD_URL"
		}
		record := importItem{Record: dns.Record{Name: name, Type: kind, Value: value, TTL: max(600, minTTL), Enabled: true}, SourceRow: rowNum, Valid: true}
		issue := func(code, message string) {
			record.Valid = false
			p.Issues = append(p.Issues, importNotice{rowNum, code, message})
		}
		if raw := column("ttl"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 {
				issue("invalid_ttl", "TTL 需为正整数")
			} else {
				record.TTL = n
				if n < minTTL {
					record.TTL = minTTL
					p.Warnings = append(p.Warnings, importNotice{rowNum, "ttl_adjusted", fmt.Sprintf("TTL 已从 %d 调整为平台最小值 %d", n, minTTL)})
				}
			}
		}
		if raw := column("weight"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 {
				issue("invalid_weight", "权重需为非负整数")
			} else {
				record.Weight = &n
			}
		}
		record.Remark = column("remark")
		if kind == "MX" {
			priority := 1
			if match := importMXValue.FindStringSubmatch(value); len(match) > 0 {
				record.Value = match[1]
				priority, _ = strconv.Atoi(match[2])
			}
			if raw := column("priority"); raw != "" {
				n, err := strconv.Atoi(raw)
				if err != nil {
					issue("invalid_priority", "MX 优先级需为 0–65535")
				} else {
					priority = n
				}
			}
			record.Priority = &priority
		}
		requested := column("line")
		line, found := byLine[requested]
		if !found {
			line, found = byLine[canonicalImportLine(requested)]
		}
		if !found {
			line = defaultLine
			record.LineFallback = requested != "" && canonicalImportLine(requested) != "默认"
		}
		record.Line, record.LineName = line.ID, line.Name
		if record.LineFallback {
			p.Warnings = append(p.Warnings, importNotice{rowNum, "line_fallback", fmt.Sprintf("线路“%s”未匹配，使用“%s”", requested, line.Name)})
		}
		if (kind == "REDIRECT_URL" || kind == "FORWARD_URL") && !caps.Redirect {
			issue("unsupported_redirect", "此平台不支持 URL 跳转记录")
		}
		if err := dns.ValidateRecord(record.Record, zone); err != nil {
			issue("invalid_record", err.Error())
		}
		p.Items = append(p.Items, record)
	}
	return p, nil
}

func canonicalImportLine(value string) string {
	name := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		if strings.ContainsRune("＿－—–-", r) {
			return '_'
		}
		return r
	}, value)
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	name = strings.Trim(name, "_")
	aliases := map[string]string{"全网默认": "默认", "默认线路": "默认", "default": "默认", "中国地区": "境内", "中国大陆": "境内", "中国内地": "境内", "海外": "境外", "海外线路": "境外", "worldwide": "境外", "全球(不含中国内地)": "境外", "港澳台及海外": "境外", "搜索引擎线路": "搜索引擎", "电信通/长宽": "长城宽带", "方正": "方正宽带", "华数": "华数宽带", "中国港澳台": "港澳台地区", "东非洲地区": "东非地区", "南非洲地区": "南非地区", "西非洲地区": "西非地区", "北非洲地区": "北非地区", "中非洲地区": "中非地区", "亚太地区": "亚洲", "northamerica": "北美洲", "southamerica": "南美洲", "europe": "欧洲", "asia": "亚洲", "oceania": "大洋洲", "africa": "非洲"}
	if alias := aliases[strings.ToLower(name)]; alias != "" {
		return alias
	}
	name = importRegion.ReplaceAllString(name, "$1")
	prefixes := []string{"中国地区_", "中国大陆_", "中国_", "东北_", "华东_", "华中_", "华南_", "西北_", "西南_", "非洲_", "亚洲_", "欧洲_", "北美洲_", "南美洲_", "大洋洲_", "全球_"}
	for {
		previous := name
		for _, prefix := range prefixes {
			name = strings.TrimPrefix(name, prefix)
		}
		if name == previous {
			break
		}
	}
	name = importCarrier.ReplaceAllString(name, "$1")
	for _, carrier := range []string{"移动", "联通", "电信", "教育网", "广电", "铁通", "鹏博士", "科技网"} {
		if name != carrier && strings.HasSuffix(name, carrier) {
			name = carrier + "_" + strings.TrimSuffix(strings.TrimSuffix(name, carrier), "_")
			break
		}
	}
	if alias := aliases[strings.ToLower(name)]; alias != "" {
		return alias
	}
	return name
}
