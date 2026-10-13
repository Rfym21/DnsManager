package database

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	u.RawQuery = url.Values{"_pragma": {"busy_timeout(10000)", "foreign_keys(1)", "journal_mode(WAL)"}, "_txlock": {"immediate"}}.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.PingContext(context.Background()); err != nil {
		t.Fatalf("SQLite URL %s: %v", u.String(), err)
	}
}
