package migrations

import (
	"context"
	"database/sql"
	"io/fs"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

func TestFilesForSelectsMatchingVersionHistory(t *testing.T) {
	expected, err := fs.Glob(Files, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, driver := range []string{"mysql", "postgres", "postgresql", "pgx", "sqlite", "sqlite3", " PostgreSQL "} {
		t.Run(driver, func(t *testing.T) {
			files, err := FilesFor(driver)
			if err != nil {
				t.Fatal(err)
			}
			versions, err := fs.Glob(files, "*.sql")
			if err != nil || !reflect.DeepEqual(versions, expected) {
				t.Fatalf("migration versions: %v, error: %v", versions, err)
			}
			for _, version := range versions {
				ddl, err := fs.ReadFile(files, version)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(ddl), "-- +goose Up") || !strings.Contains(string(ddl), "-- +goose Down") {
					t.Errorf("%s has no migration directions", version)
				}
			}
		})
	}
	if _, err := FilesFor("unknown"); err == nil {
		t.Fatal("unsupported driver accepted")
	}
}

func TestNewDialectsPreserveTablesAndIndexes(t *testing.T) {
	versions, err := fs.Glob(Files, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	tablePattern := regexp.MustCompile(`CREATE TABLE (\w+)`)
	indexPattern := regexp.MustCompile(`(?m)^    INDEX (\w+) `)
	for _, driver := range []string{"postgres", "sqlite"} {
		files, err := FilesFor(driver)
		if err != nil {
			t.Fatal(err)
		}
		for _, version := range versions {
			original, err := fs.ReadFile(Files, version)
			if err != nil {
				t.Fatal(err)
			}
			ddl, err := fs.ReadFile(files, version)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tablePattern.FindAllSubmatch(original, -1), tablePattern.FindAllSubmatch(ddl, -1)) {
				t.Errorf("%s/%s changed the table set", driver, version)
			}
			for _, index := range indexPattern.FindAllStringSubmatch(string(original), -1) {
				if !strings.Contains(string(ddl), "CREATE INDEX "+index[1]+" ON ") {
					t.Errorf("%s/%s omitted index %s", driver, version, index[1])
				}
			}
			for _, mysqlOnly := range []string{"AUTO_INCREMENT", "LONGTEXT", "MEDIUMTEXT", "UNIQUE KEY", "DATETIME(6)"} {
				if strings.Contains(string(ddl), mysqlOnly) {
					t.Errorf("%s/%s contains %s", driver, version, mysqlOnly)
				}
			}
		}
	}
}

func sqliteProvider(t *testing.T) (*sql.DB, *goose.Provider) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/schema.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	files, err := FilesFor("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, files)
	if err != nil {
		t.Fatal(err)
	}
	return db, provider
}

func TestSQLiteSchemaUpgradeDowngradeAndReapply(t *testing.T) {
	db, provider := sqliteProvider(t)
	ctx := context.Background()
	for version := int64(1); version <= 7; version++ {
		if _, err := provider.UpTo(ctx, version); err != nil {
			t.Fatalf("upgrade to %d: %v", version, err)
		}
		actual, err := provider.GetDBVersion(ctx)
		if err != nil || actual != version {
			t.Fatalf("version %d: got %d, %v", version, actual, err)
		}
	}
	assertSQLiteTables(t, db)
	if _, err := provider.DownTo(ctx, 0); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	var tables int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'goose_db_version'").Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("tables after downgrade: %d, %v", tables, err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	assertSQLiteTables(t, db)
}

func assertSQLiteTables(t *testing.T, db *sql.DB) {
	t.Helper()
	versions, err := fs.Glob(Files, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`CREATE TABLE (\w+)`)
	var expected []string
	for _, version := range versions {
		ddl, err := fs.ReadFile(Files, version)
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range pattern.FindAllStringSubmatch(string(ddl), -1) {
			expected = append(expected, table[1])
		}
	}
	sort.Strings(expected)
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'goose_db_version' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actual []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		actual = append(actual, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("tables: got %v, want %v", actual, expected)
	}
}

func TestSQLiteConstraintsAndValueRoundTrips(t *testing.T) {
	db, provider := sqliteProvider(t)
	ctx := context.Background()
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.October, 13, 11, 12, 13, 123456000, time.UTC)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO users(id,username,password_hash,role,preferences,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", "user", "Admin", "hash", "admin", []byte(`{"theme":"dark"}`), now, now)
	var enabled, totpEnabled bool
	var created time.Time
	if err := db.QueryRow("SELECT enabled,totp_enabled,created_at FROM users WHERE id='user'").Scan(&enabled, &totpEnabled, &created); err != nil {
		t.Fatal(err)
	}
	if !enabled || totpEnabled || !created.Equal(now) || created.Location() != time.UTC {
		t.Fatalf("boolean/time round trip: %v, %v, %v", enabled, totpEnabled, created)
	}
	var preferences []byte
	if err := db.QueryRow("SELECT preferences FROM users WHERE id='user'").Scan(&preferences); err != nil || string(preferences) != `{"theme":"dark"}` {
		t.Fatalf("JSON byte round trip: %q, %v", preferences, err)
	}
	if _, err := db.Exec("INSERT INTO users(id,username,password_hash,role,preferences,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", "duplicate", "admin", "hash", "admin", `{}`, now, now); err == nil {
		t.Fatal("case-insensitive username uniqueness was not enforced")
	}
	if _, err := db.Exec("INSERT INTO users(id,username,password_hash,role,preferences,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", nil, "null-id", "hash", "admin", `{}`, now, now); err == nil {
		t.Fatal("text primary key accepted NULL")
	}
	if _, err := db.Exec("UPDATE users SET preferences='invalid-json' WHERE id='user'"); err == nil {
		t.Fatal("JSON validation was not enforced")
	}
	if _, err := db.Exec("INSERT INTO domain_grants(user_id,domain_id,permissions) VALUES('missing','domain','[]')"); err == nil {
		t.Fatal("foreign key was not enforced")
	}
	exec("INSERT INTO domain_grants(user_id,domain_id,permissions) VALUES('user','domain','[]')")
	exec("DELETE FROM users WHERE id='user'")
	var grants int
	if err := db.QueryRow("SELECT COUNT(*) FROM domain_grants").Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("user cascade: %d, %v", grants, err)
	}
	for _, id := range []string{"job-a", "job-b"} {
		exec("INSERT INTO jobs(id,kind,resource_id,owner_id,payload_ciphertext,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", id, "test", id, "user", "ciphertext", now, now, now)
	}
	exec("UPDATE jobs SET occurrence_key='once' WHERE id='job-a'")
	if _, err := db.Exec("UPDATE jobs SET occurrence_key='once' WHERE id='job-b'"); err == nil {
		t.Fatal("occurrence uniqueness was not enforced")
	}
	exec("INSERT INTO job_events(id,job_id,level,message,created_at) VALUES(41,'job-a','info','restored',?)", now)
	if _, err := db.Exec("UPDATE job_events SET data='invalid-json' WHERE id=41"); err == nil {
		t.Fatal("nullable JSON validation was not enforced")
	}
	result, err := db.Exec("INSERT INTO job_events(job_id,level,message,created_at) VALUES('job-a','info','new',?)", now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 41 {
		t.Fatalf("autoincrement after explicit ID: %d, %v", id, err)
	}
	exec("DELETE FROM jobs WHERE id='job-a'")
	var events int
	if err := db.QueryRow("SELECT COUNT(*) FROM job_events").Scan(&events); err != nil || events != 0 {
		t.Fatalf("job event cascade: %d, %v", events, err)
	}
}
