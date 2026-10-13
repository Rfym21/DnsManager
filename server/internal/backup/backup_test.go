package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/database"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func isolated(t *testing.T, env string, box *cryptobox.Box) *store.Store {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		t.Skip("dedicated backup source and restore databases required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	s, e := store.Open(context.Background(), strings.TrimSpace(string(raw)), box)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	return s
}
func clear(t *testing.T, s *store.Store) {
	t.Helper()
	defs, _, e := schema(context.Background(), s.DB, s.Dialect())
	if e != nil {
		t.Fatal(e)
	}
	list := []TableData{}
	for _, d := range defs {
		list = append(list, TableData{Definition: d})
	}
	ordered, e := insertionOrder(list)
	if e != nil {
		t.Fatal(e)
	}
	for i := len(ordered) - 1; i >= 0; i-- {
		name := ordered[i].Definition.Name
		if name != "goose_db_version" {
			if _, e = s.DB.Exec("DELETE FROM " + quote(s.Dialect(), name)); e != nil {
				t.Fatal(e)
			}
		}
	}
}
func seed(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	enc := func(scope string, v any) string {
		b, e := s.Encrypt(scope, v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	exec := func(q string, args ...any) {
		if _, e := s.DB.ExecContext(ctx, q, args...); e != nil {
			t.Fatal("seed query failed", e)
		}
	}
	exec("INSERT INTO users(id,username,password_hash,role,preferences,created_at,updated_at) VALUES('user','backup-fixture','$2y$fixture','admin','{}','2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456')")
	exec("INSERT INTO provider_accounts(id,name,provider,config_ciphertext,created_at,updated_at) VALUES('account','fixture','cloudflare',?,'2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456')", enc("account:account", map[string]string{"api_token": "fixture-sensitive-api"}))
	exec("INSERT INTO domains(id,account_id,provider_domain_id,name,ascii_name,created_at,updated_at) VALUES('domain','account','zone','fixture.example.invalid','fixture.example.invalid','2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456')")
	exec("INSERT INTO domain_grants(user_id,domain_id,permissions) VALUES('user','domain','[\"dns:read\"]')")
	exec("INSERT INTO objects(id,kind,name,domain_id,owner_id,data_ciphertext,active,created_at,updated_at) VALUES('object','schedules','fixture','domain','user',?,FALSE,'2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456')", enc("object:object", map[string]any{"record_id": "remote", "private_key": "fixture-sensitive-key"}))
	exec("INSERT INTO jobs(id,kind,resource_id,owner_id,payload_ciphertext,state,next_run_at,created_at,updated_at,checkpoint_ciphertext,result_ciphertext,context_ciphertext) VALUES('job','schedules','object','user',?,'succeeded','2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456',?,?,?)", enc("job-payload:job", map[string]any{"fixture": true}), enc("job-checkpoint:job", map[string]any{"stage": "done"}), enc("job-result:job", map[string]any{"ok": true}), enc("job-context:job", map[string]any{"domain_id": "domain"}))
	exec("INSERT INTO job_events(job_id,level,message,data,created_at) VALUES('job','info','fixture','{\"ok\":true}','2026-01-01 01:02:03.123456')")
	exec("INSERT INTO job_items(job_id,item_index,resource_id,state,detail_ciphertext,updated_at) VALUES('job',0,'remote','succeeded',?,'2026-01-01 01:02:03.123456')", enc("job-item:job:0", map[string]any{"ok": true}))
	exec("INSERT INTO settings(name,ciphertext,updated_at) VALUES('fixture',?,'2026-01-01 01:02:03.123456')", enc("setting:fixture", map[string]any{"token": "fixture-sensitive-setting"}))
	exec("INSERT INTO notification_outbox(id,event_key,channel_id,payload_ciphertext,state,next_run_at,created_at,updated_at) VALUES('notification','event-key','object',?,'sent','2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456')", enc("notification:notification", map[string]any{"body": "fixture-sensitive-body"}))
	exec("INSERT INTO business_events(id,event_key,payload_ciphertext,dispatched_at,created_at) VALUES('event','business-event',?,'2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456')", enc("business-event:event", map[string]any{"title": "fixture"}))
	exec("INSERT INTO dns_challenge_intents(job_id,challenge_key,domain_id,intent_ciphertext,state,record_id,created_at,updated_at) VALUES('job','challenge','domain',?,'confirmed','remote','2026-01-01 01:02:03.123456','2026-01-01 01:02:03.123456')", enc("dns-intent:job:challenge", map[string]any{"value": "fixture-sensitive-challenge"}))
	exec("INSERT INTO migration_manifests(id,source_id,archive_ciphertext,report,created_at) VALUES('manifest','legacy',?,'{}','2026-01-01 01:02:03.123456')", enc("migration-manifest:manifest", map[string]any{"tables": map[string]any{}}))
}
func TestBackupRestoreAllTablesEncryptionAndFK(t *testing.T) {
	box, _ := cryptobox.New(make([]byte, 32))
	source := isolated(t, "BACKUP_TEST_SOURCE_DSN_FILE", box)
	target := isolated(t, "BACKUP_TEST_TARGET_DSN_FILE", box)
	testBackupRestore(t, box, source, target)
}

func TestPostgreSQLBackupRestoreAllTablesEncryptionAndFK(t *testing.T) {
	box, _ := cryptobox.New(make([]byte, 32))
	var source, target *store.Store
	if filename := os.Getenv("TEST_POSTGRES_DATABASE_DSN_FILE"); filename != "" {
		source, target = postgresStores(t, filename, box)
	} else {
		source = isolated(t, "BACKUP_TEST_POSTGRES_SOURCE_DSN_FILE", box)
		target = isolated(t, "BACKUP_TEST_POSTGRES_TARGET_DSN_FILE", box)
	}
	if source.Dialect() != database.PostgreSQL || target.Dialect() != database.PostgreSQL {
		t.Fatal("PostgreSQL backup tests require PostgreSQL fixture databases")
	}
	testBackupRestore(t, box, source, target)
}

func postgresStores(t *testing.T, filename string, box *cryptobox.Box) (*store.Store, *store.Store) {
	t.Helper()
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal("cannot read PostgreSQL backup test DSN file")
	}
	parsed, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("PostgreSQL backup test DSN must be a PostgreSQL URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base, err := store.Open(ctx, parsed.String(), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	fixture := func() *store.Store {
		id, err := store.ID()
		if err != nil {
			t.Fatal(err)
		}
		name := "test_backup_" + id
		if _, err = base.DB.ExecContext(ctx, "CREATE SCHEMA "+quote(database.PostgreSQL, name)); err != nil {
			t.Fatal("cannot create isolated PostgreSQL backup schema", err)
		}
		t.Cleanup(func() {
			if _, err := base.DB.ExecContext(context.Background(), "DROP SCHEMA "+quote(database.PostgreSQL, name)+" CASCADE"); err != nil {
				t.Error("cannot remove isolated PostgreSQL backup schema", err)
			}
		})
		copyURL := *parsed
		query := copyURL.Query()
		query.Set("search_path", name)
		copyURL.RawQuery = query.Encode()
		s, err := store.Open(ctx, copyURL.String(), box)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		if err = s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	return fixture(), fixture()
}

func sqliteStore(t *testing.T, box *cryptobox.Box) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), "sqlite:"+filepath.Join(t.TempDir(), "backup.sqlite"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSQLiteBackupRestoreAllTablesEncryptionAndFK(t *testing.T) {
	box, _ := cryptobox.New(make([]byte, 32))
	testBackupRestore(t, box, sqliteStore(t, box), sqliteStore(t, box))
}

func testBackupRestore(t *testing.T, box *cryptobox.Box, source, target *store.Store) {
	t.Helper()
	clear(t, source)
	clear(t, target)
	t.Cleanup(func() { clear(t, source); clear(t, target) })
	seed(t, source)
	ctx := context.Background()
	if _, _, e := Capture(ctx, source, false); e == nil {
		t.Fatal("backup without freeze accepted")
	}
	snapshot, report, e := Capture(ctx, source, true)
	if e != nil || len(report.Counts) != len(Tables) {
		t.Fatal("capture", report, e)
	}
	if snapshot.Dialect != string(source.Dialect()) {
		t.Fatal("snapshot omitted source database dialect")
	}
	archive := filepath.Join(t.TempDir(), "backup.enc")
	if e = Write(archive, box, snapshot); e != nil {
		t.Fatal(e)
	}
	if e = Write(archive, box, snapshot); e == nil {
		t.Fatal("backup overwrote archive")
	}
	raw, _ := os.ReadFile(archive)
	if strings.Contains(string(raw), "fixture-sensitive") {
		t.Fatal("backup leaked secrets")
	}
	wrong, _ := cryptobox.New([]byte("12345678901234567890123456789012"))
	if _, e = Read(archive, wrong); e == nil {
		t.Fatal("wrong master key accepted")
	}
	restored, e := Read(archive, box)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Restore(ctx, target, restored, false, false); e == nil {
		t.Fatal("restore without freeze accepted")
	}
	if target.Dialect() == database.MySQL {
		legacy := restored
		legacy.Dialect = ""
		if _, e = Restore(ctx, target, legacy, true, true); e != nil {
			t.Fatal("legacy MySQL backup compatibility", e)
		}
	}
	if _, e = Restore(ctx, target, restored, true, true); e != nil {
		t.Fatal("dry-run restore", e)
	}
	var count int
	if e = target.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); e != nil || count != 0 {
		t.Fatal("dry-run wrote rows", e)
	}
	if _, e = Restore(ctx, target, restored, true, false); e != nil {
		t.Fatal("restore", e)
	}
	// An explicit restored identity must not collide with the next generated ID.
	if source.Dialect() == database.PostgreSQL || source.Dialect() == database.SQLite {
		var firstID int64
		if e = target.DB.QueryRow("SELECT MAX(id) FROM job_events").Scan(&firstID); e != nil {
			t.Fatal(e)
		}
		if _, e = target.DB.Exec("INSERT INTO job_events(job_id,level,message,created_at) VALUES('job','info','identity-fixture',?)", time.Now().UTC()); e != nil {
			t.Fatal("restored generated identity collided", e)
		}
		var nextID int64
		if e = target.DB.QueryRow("SELECT MAX(id) FROM job_events").Scan(&nextID); e != nil || nextID <= firstID {
			t.Fatal("restored generated identity did not advance", e)
		}
		if _, e = target.DB.Exec("DELETE FROM job_events WHERE id=?", nextID); e != nil {
			t.Fatal(e)
		}
	}
	after, _, e := Capture(ctx, target, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, beforeTable := range snapshot.Tables {
		if beforeTable.Definition.Name == "goose_db_version" {
			continue
		}
		for _, afterTable := range after.Tables {
			if afterTable.Definition.Name == beforeTable.Definition.Name && !reflect.DeepEqual(beforeTable.Rows, afterTable.Rows) {
				t.Fatal("restore changed row values", beforeTable.Definition.Name)
			}
		}
	}
	account, e := target.Account(ctx, "account")
	if e != nil || account.Config["api_token"] != "fixture-sensitive-api" {
		t.Fatal("restored credentials unreadable", e)
	}
	if _, e = Restore(ctx, target, restored, true, false); e == nil {
		t.Fatal("nonempty target restore accepted")
	}
	clear(t, target)
	corrupt := restored
	corrupt.SchemaVersion++
	if _, e = Restore(ctx, target, corrupt, true, false); e == nil {
		t.Fatal("wrong schema version accepted")
	}
	corrupt = restored
	if target.Dialect() == database.SQLite {
		corrupt.Dialect = string(database.PostgreSQL)
	} else {
		corrupt.Dialect = string(database.SQLite)
	}
	if _, e = Restore(ctx, target, corrupt, true, false); e == nil {
		t.Fatal("cross-engine restore accepted")
	}
	if target.Dialect() != database.MySQL {
		corrupt.Dialect = ""
		if _, e = Restore(ctx, target, corrupt, true, false); e == nil {
			t.Fatal("legacy MySQL archive accepted by another engine")
		}
	}
	source.Box = wrong
	if _, _, e = Capture(ctx, source, true); e == nil {
		t.Fatal("wrong key backed up unreadable inner ciphertext")
	}
	source.Box = box
	// FK errors occur inside the restore transaction and roll back all inserts.
	rawSnapshot, _ := json.Marshal(restored)
	var orphan Snapshot
	_ = json.Unmarshal(rawSnapshot, &orphan)
	for ti := range orphan.Tables {
		table := &orphan.Tables[ti]
		if table.Definition.Name == "domains" {
			for ci, col := range table.Definition.Columns {
				if col.Name == "account_id" {
					table.Rows[0][ci] = Cell{Kind: "text", Value: "absent"}
				}
			}
		}
	}
	if _, e = Restore(ctx, target, orphan, true, false); e == nil {
		t.Fatal("orphan restored with FK checks bypassed")
	}
	if e = target.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); e != nil || count != 0 {
		t.Fatal("failed restore committed partial data", e)
	}
	var created time.Time
	if e = source.DB.QueryRow("SELECT created_at FROM users WHERE id='user'").Scan(&created); e != nil || created.Nanosecond() != 123456000 {
		t.Fatal("fixture lost UTC microsecond date", e)
	}
	var nullable sql.NullString
	if e = source.DB.QueryRow("SELECT totp_secret FROM users WHERE id='user'").Scan(&nullable); e != nil || nullable.Valid {
		t.Fatal("fixture NULL semantics", e)
	}
}

func TestSQLiteBackupRejectsSchemaChanges(t *testing.T) {
	box, _ := cryptobox.New(make([]byte, 32))
	source, target := sqliteStore(t, box), sqliteStore(t, box)
	ctx := context.Background()
	snapshot, _, err := Capture(ctx, source, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.DB.Exec("CREATE TABLE unrelated_secret(id INTEGER PRIMARY KEY, secret TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = Capture(ctx, source, true); err == nil {
		t.Fatal("backup silently included or ignored an unknown application table")
	}
	if _, err = source.DB.Exec("DROP TABLE unrelated_secret"); err != nil {
		t.Fatal(err)
	}
	if _, err = target.DB.Exec("ALTER TABLE users ADD COLUMN unexpected TEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(ctx, target, snapshot, true, false); err == nil {
		t.Fatal("restore accepted different target column schema")
	}
	if _, err = source.DB.Exec("ALTER TABLE users ADD COLUMN generated TEXT GENERATED ALWAYS AS (username) VIRTUAL"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = Capture(ctx, source, true); err == nil {
		t.Fatal("backup accepted a generated column that cannot be restored")
	}
}
