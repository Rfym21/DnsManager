package httpapi

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/xuri/excelize/v2"
)

func TestExcelImportRealFormats(t *testing.T) {
	book := excelize.NewFile()
	book.SetSheetName("Sheet1", "English records")
	rows := [][]any{{"Name", "Type", "LineName", "Value", "TTL", "Weight", "Remark"}, {"www", "A", "中国电信", "192.0.2.10", 300, 2, "fixture"}, {"mail", "MX", "默认", "mx.example.test | 20", 600, 0, ""}, {"@", "NS", "默认", "ns.example.test", 600, 0, ""}, {"@", "SOA", "默认", "ignored", 600, 0, ""}, {"go", "显性URL", "未知线路", "https://example.test", 30, 0, ""}, {"hidden", "隐性URL", "默认", "https://example.test", 600, 0, ""}}
	for i, row := range rows {
		cell, _ := excelize.CoordinatesToCellName(1, i+1)
		if err := book.SetSheetRow("English records", cell, &row); err != nil {
			t.Fatal(err)
		}
	}
	book.NewSheet("Do not import")
	book.SetCellValue("Do not import", "A1", "ignored")
	buf, err := book.WriteToBuffer()
	if err != nil {
		t.Fatal(err)
	}
	book.Close()
	xls, err := os.ReadFile("testdata/records-cn.xls")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		ext   string
		data  []byte
		sheet string
	}{{".xlsx", buf.Bytes(), "English records"}, {".xls", xls, "记录导入"}} {
		t.Run(fixture.ext, func(t *testing.T) {
			parsed, sheet, err := readImportWorkbook(context.Background(), fixture.data, fixture.ext)
			if err != nil {
				t.Fatal(err)
			}
			if sheet != fixture.sheet || len(parsed) != 7 {
				t.Fatalf("first worksheet incorrect: %s rows=%d", sheet, len(parsed))
			}
			preview, err := normalizeImportRows(parsed, []dns.Line{{ID: "default", Name: "默认"}, {ID: "telecom", Name: "电信"}}, 60, "example.test", dns.Capabilities{Redirect: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(preview.Items) != 4 || len(preview.Issues) != 0 {
				t.Fatalf("preview items=%d issues=%v", len(preview.Items), preview.Issues)
			}
			if preview.Items[0].Line != "telecom" || preview.Items[1].Value != "mx.example.test" || *preview.Items[1].Priority != 20 {
				t.Fatalf("line/MX mismatch: %+v", preview.Items)
			}
			if preview.Items[2].Type != "REDIRECT_URL" || preview.Items[3].Type != "FORWARD_URL" || preview.Items[2].TTL != 60 || !preview.Items[2].LineFallback {
				t.Fatalf("URL/TTL/fallback mismatch: %+v", preview.Items[2])
			}
			if len(preview.Warnings) != 4 {
				t.Fatalf("expected authority skips/TTL/line notices: %v", preview.Warnings)
			}
		})
	}
}

func TestExcelImportInvalidRowsAreVisible(t *testing.T) {
	rows := [][]string{{"Name", "Type", "Value", "TTL", "Priority"}, {"bad", "A", "999.0.0.1", "bad", ""}, {"mail", "MX", "mx.example.test", "300", "65536"}, {"redirect", "显性URL", "https://example.test", "300", ""}}
	p, err := normalizeImportRows(rows, nil, 1, "example.test", dns.Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 3 || len(p.Issues) < 3 {
		t.Fatalf("invalid rows lost: %+v", p)
	}
	for _, row := range p.Items {
		if row.Valid {
			t.Fatalf("invalid row accepted: %+v", row)
		}
	}
	if _, err := normalizeImportRows([][]string{{"Name", "name", "Type", "Value"}}, nil, 1, "example.test", dns.Capabilities{}); err == nil {
		t.Fatal("duplicate alias headers accepted")
	}
}

func TestExcelImportRejectsMalformedAndLargeWorkbook(t *testing.T) {
	for _, ext := range []string{".xls", ".xlsx"} {
		if _, _, err := readImportWorkbook(context.Background(), []byte("broken"), ext); err == nil {
			t.Fatalf("malformed %s accepted", ext)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	budget := importReadBudget{Reader: bytes.NewReader([]byte("fixture")), ctx: ctx, remaining: 10}
	if _, err := budget.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancelled reader accepted")
	}
	book := excelize.NewFile()
	for i := 1; i <= importMaxRows+2; i++ {
		cell, _ := excelize.CoordinatesToCellName(1, i)
		book.SetCellValue("Sheet1", cell, "value")
	}
	buf, err := book.WriteToBuffer()
	if err != nil {
		t.Fatal(err)
	}
	book.Close()
	if _, _, err := readImportWorkbook(context.Background(), buf.Bytes(), ".xlsx"); err == nil || !strings.Contains(err.Error(), "5000") {
		t.Fatalf("row limit missing: %v", err)
	}
}
