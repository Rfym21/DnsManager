package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRewriteSupportedStatements(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		pg     []string
		sqlite []string
		absent []string
	}{
		{
			name:   "quoted literals and identifiers",
			query:  "SELECT `id`, '?', 'it''s ? DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 DAY)', \"?\" FROM settings WHERE name=?",
			pg:     []string{`SELECT "id"`, "'?'", "'it''s ? DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 DAY)'", `"?"`, "WHERE name=$1"},
			sqlite: []string{"`id`", "'it''s ? DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 1 DAY)'", "WHERE name=?"},
		},
		{
			name:   "nested dynamic interval and row locks",
			query:  "SELECT id FROM jobs WHERE lease_until<DATE_SUB(DATE_ADD(UTC_TIMESTAMP(6),INTERVAL ? MINUTE),INTERVAL 1 SECOND) LIMIT 1 FOR UPDATE SKIP LOCKED",
			pg:     []string{"clock_timestamp()", "($1) * INTERVAL '1 minute'", "(1) * INTERVAL '1 second'", "FOR UPDATE SKIP LOCKED"},
			sqlite: []string{"strftime('%Y-%m-%d %H:%M:%f'", "'+' || (?) || ' minute'", "'-' || (1) || ' second'"},
			absent: []string{"DATE_ADD(", "DATE_SUB(", "UTC_TIMESTAMP("},
		},
		{
			name:   "setting upsert qualification",
			query:  "INSERT INTO settings(name,ciphertext,updated_at) VALUES(?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE ciphertext=VALUES(ciphertext),version=version+1,updated_at=UTC_TIMESTAMP(6)",
			pg:     []string{"VALUES($1,$2,clock_timestamp())", "ON CONFLICT(name) DO UPDATE SET", "ciphertext=excluded.ciphertext", "version=settings.version+1"},
			sqlite: []string{"ON CONFLICT(name) DO UPDATE SET", "ciphertext=excluded.ciphertext", "version=settings.version+1"},
			absent: []string{"ON DUPLICATE", "VALUES(ciphertext)"},
		},
		{
			name:   "nested login expiry upsert",
			query:  "INSERT INTO login_attempts (attempt_key,failures,expires_at) VALUES (?,1,DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 15 MINUTE)) ON DUPLICATE KEY UPDATE failures=IF(expires_at<UTC_TIMESTAMP(6),1,failures+1),expires_at=IF(expires_at<UTC_TIMESTAMP(6),DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 15 MINUTE),expires_at)",
			pg:     []string{"ON CONFLICT(attempt_key)", "CASE WHEN login_attempts.expires_at<clock_timestamp() THEN 1 ELSE login_attempts.failures+1 END", "ELSE login_attempts.expires_at END"},
			sqlite: []string{"ON CONFLICT(attempt_key)", "CASE WHEN login_attempts.expires_at<", "ELSE login_attempts.failures+1 END"},
			absent: []string{"IF(", "DATE_ADD(", "ON DUPLICATE"},
		},
		{
			name:   "composite key upsert",
			query:  "INSERT INTO job_items(job_id,item_index,state) VALUES(?,?,?) ON DUPLICATE KEY UPDATE state=VALUES(state)",
			pg:     []string{"ON CONFLICT(job_id,item_index) DO UPDATE SET state=excluded.state", "VALUES($1,$2,$3)"},
			sqlite: []string{"ON CONFLICT(job_id,item_index) DO UPDATE SET state=excluded.state"},
		},
		{
			name:   "idempotent insert preserves transaction",
			query:  "INSERT IGNORE INTO business_events(id,event_key,payload_ciphertext,created_at) VALUES(?,?,?,UTC_TIMESTAMP(6))",
			pg:     []string{"INSERT INTO business_events", "ON CONFLICT DO NOTHING", "VALUES($1,$2,$3,clock_timestamp())"},
			sqlite: []string{"INSERT INTO business_events", "ON CONFLICT DO NOTHING"},
			absent: []string{"INSERT IGNORE"},
		},
		{
			name:   "boolean aggregates",
			query:  "SELECT COALESCE(SUM(state='unknown'),0),COALESCE(SUM(state IN ('queued','running','retry')),0) FROM jobs WHERE resource_id=?",
			pg:     []string{"SUM(CASE WHEN state='unknown' THEN 1 ELSE 0 END)", "SUM(CASE WHEN state IN('queued','running','retry') THEN 1 ELSE 0 END)", "resource_id=$1"},
			sqlite: []string{"SUM(CASE WHEN state='unknown' THEN 1 ELSE 0 END)"},
		},
		{
			name:   "cancel case and retry clamp",
			query:  "UPDATE jobs SET state=IF(state IN ('queued','retry'),'cancelled',state),attempt=GREATEST(attempt-1,0) WHERE id=?",
			pg:     []string{"CASE WHEN state IN('queued','retry') THEN 'cancelled' ELSE state END", "GREATEST(attempt-1,0)", "id=$1"},
			sqlite: []string{"CASE WHEN state IN('queued','retry') THEN 'cancelled' ELSE state END", "MAX(attempt-1,0)"},
			absent: []string{"IF("},
		},
		{
			name:   "bounded retention preserves correlated evidence",
			query:  "DELETE FROM jobs WHERE state IN ('succeeded','failed','cancelled','partial') AND updated_at<? AND NOT EXISTS(SELECT 1 FROM business_events b WHERE b.event_key LIKE CONCAT('%',jobs.id,'%') AND b.dispatched_at IS NULL) LIMIT 100",
			pg:     []string{"DELETE FROM jobs WHERE ctid IN (SELECT ctid FROM jobs WHERE", "updated_at<$1", "b.event_key LIKE ('%' || jobs.id || '%')", "LIMIT 100)"},
			sqlite: []string{"DELETE FROM jobs WHERE rowid IN (SELECT rowid FROM jobs WHERE", "updated_at<?", "b.event_key LIKE ('%' || jobs.id || '%')", "LIMIT 100)"},
			absent: []string{"CONCAT("},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Rewrite(MySQL, tt.query); got != tt.query {
				t.Fatalf("MySQL statement was changed:\n%s", got)
			}
			for _, dialect := range []Dialect{PostgreSQL, SQLite} {
				got := Rewrite(dialect, tt.query)
				wanted := tt.pg
				if dialect == SQLite {
					wanted = tt.sqlite
				}
				for _, fragment := range wanted {
					if !strings.Contains(got, fragment) {
						t.Errorf("%s statement does not contain %q:\n%s", dialect, fragment, got)
					}
				}
				for _, fragment := range tt.absent {
					if strings.Contains(got, fragment) {
						t.Errorf("%s statement retained %q:\n%s", dialect, fragment, got)
					}
				}
				if dialect == SQLite && strings.Contains(got, "FOR UPDATE") {
					t.Errorf("SQLite retained an unsupported row lock:\n%s", got)
				}
			}
		})
	}
}

func TestRewriteDoesNotChangeLiteralTextOrSQLComments(t *testing.T) {
	query := "/* ? UTC_TIMESTAMP(6) */ SELECT ' FOR UPDATE SKIP LOCKED', 'INSERT IGNORE INTO x', ' ON DUPLICATE KEY UPDATE x=VALUES(x)', '?' AS literal, ? AS parameter -- ? UTC_TIMESTAMP(6)\n/* ? DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 DAY) */"
	for _, dialect := range []Dialect{PostgreSQL, SQLite} {
		got := Rewrite(dialect, query)
		for _, fragment := range []string{"' FOR UPDATE SKIP LOCKED'", "'INSERT IGNORE INTO x'", "' ON DUPLICATE KEY UPDATE x=VALUES(x)'", "'?' AS literal", "-- ? UTC_TIMESTAMP(6)", "/* ? DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 DAY) */"} {
			if !strings.Contains(got, fragment) {
				t.Errorf("%s rewrite changed SQL literal or comment %q:\n%s", dialect, fragment, got)
			}
		}
		if dialect == PostgreSQL && !strings.Contains(got, "$1 AS parameter") {
			t.Fatalf("actual PostgreSQL parameter was not rebound: %s", got)
		}
	}
}

func TestRewriteDoesNotFindUpsertInsideInsertLiteral(t *testing.T) {
	query := "INSERT INTO settings(name,ciphertext,updated_at) VALUES('fixture','literal ON DUPLICATE KEY UPDATE ciphertext=VALUES(ciphertext)',UTC_TIMESTAMP(6))"
	for _, dialect := range []Dialect{PostgreSQL, SQLite} {
		got := Rewrite(dialect, query)
		if !strings.Contains(got, "'literal ON DUPLICATE KEY UPDATE ciphertext=VALUES(ciphertext)'") {
			t.Fatalf("%s treated a literal as an upsert:\n%s", dialect, got)
		}
	}
}

func TestDuplicateClassificationIsSpecific(t *testing.T) {
	for _, err := range []error{&mysql.MySQLError{Number: 1062}, &pgconn.PgError{Code: "23505"}} {
		if !IsDuplicate(errors.Join(errors.New("wrapped database error"), err)) {
			t.Errorf("wrapped unique violation was not classified: %T", err)
		}
	}
	for _, err := range []error{nil, errors.New("duplicate data"), &mysql.MySQLError{Number: 1452}, &pgconn.PgError{Code: "23503"}} {
		if IsDuplicate(err) {
			t.Errorf("non-unique error was classified as duplicate: %v", err)
		}
	}
	db, err := Open(context.Background(), "sqlite:"+filepath.Join(t.TempDir(), "errors.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, query := range []string{"CREATE TABLE parent(id TEXT PRIMARY KEY, name TEXT UNIQUE)", "CREATE TABLE child(id TEXT PRIMARY KEY, parent_id TEXT REFERENCES parent(id))", "INSERT INTO parent(id,name) VALUES('fixture','fixture')"} {
		if _, err = db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range []string{"INSERT INTO parent(id,name) VALUES('fixture','other')", "INSERT INTO parent(id,name) VALUES('other','fixture')"} {
		_, err = db.Exec(query)
		if !IsDuplicate(err) {
			t.Fatalf("SQLite unique violation not classified: %v", err)
		}
	}
	if _, err = db.Exec("INSERT INTO child(id,parent_id) VALUES('child','missing')"); err == nil || IsDuplicate(err) {
		t.Fatalf("SQLite foreign key violation was ignored or misclassified: %v", err)
	}
}

func TestSQLiteTimeArgumentsRemainComparable(t *testing.T) {
	db, err := Open(context.Background(), "sqlite:"+filepath.Join(t.TempDir(), "timestamps.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("CREATE TABLE dates(id INTEGER PRIMARY KEY, value DATETIME NULL)"); err != nil {
		t.Fatal(err)
	}
	value := time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.FixedZone("fixture-offset", 8*60*60))
	arguments := []any{value, &value, sql.NullTime{Time: value, Valid: true}, sql.NullTime{}, (*time.Time)(nil)}
	for id, argument := range arguments {
		if _, err = db.Exec("INSERT INTO dates(id,value) VALUES(?,?)", id, argument); err != nil {
			t.Fatal(err)
		}
		var parsed sql.NullTime
		if err = db.QueryRow("SELECT value FROM dates WHERE id=?", id).Scan(&parsed); err != nil {
			t.Fatalf("timestamp argument %T did not scan: %v", argument, err)
		}
		if id >= 3 {
			if parsed.Valid {
				t.Fatalf("null timestamp argument %T became valid", argument)
			}
			continue
		}
		if !parsed.Valid || !parsed.Time.Equal(value) {
			t.Fatalf("timestamp argument %T changed instant: %v", argument, parsed)
		}
		var text string
		if err = db.QueryRow("SELECT 'raw:' || value FROM dates WHERE id=?", id).Scan(&text); err != nil {
			t.Fatal(err)
		}
		if text != "raw:"+value.UTC().Format("2006-01-02 15:04:05.000000000") {
			t.Fatalf("timestamp argument %T is not comparable with SQL UTC dates: %q", argument, text)
		}
	}
}

func TestSQLiteNewDatabaseThroughDirectoryAliasSharesResourceLocks(t *testing.T) {
	dir := t.TempDir()
	realDir, aliasDir := filepath.Join(dir, "real"), filepath.Join(dir, "alias")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, aliasDir); err != nil {
		t.Skipf("directory symlink is unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The database does not exist yet: resolving just the full path before
	// creating the file cannot resolve the alias's parent directory.
	aliased, err := Open(ctx, "sqlite:"+filepath.Join(aliasDir, "new.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer aliased.Close()
	real, err := Open(ctx, "sqlite:"+filepath.Join(realDir, "new.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	if aliased.Name() != real.Name() || aliased.LockDir() != real.LockDir() {
		t.Fatalf("database alias did not resolve to the same database and lock directory: %q / %q", aliased.Name(), real.Name())
	}
	release, err := aliased.Lock(ctx, []string{"same-remote-resource"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if peerRelease, err := real.Lock(ctx, []string{"same-remote-resource"}, 0); !errors.Is(err, ErrBusy) {
		if peerRelease != nil {
			peerRelease()
		}
		t.Fatalf("real path bypassed the directory alias's resource lock: %v", err)
	}
	release()
	peerRelease, err := real.Lock(ctx, []string{"same-remote-resource"}, 0)
	if err != nil {
		t.Fatalf("released aliased resource remained locked: %v", err)
	}
	peerRelease()
}
