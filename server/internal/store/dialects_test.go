package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
)

// SQLite fixtures are real files so separate pools exercise the same locking
// paths as separately running API and worker processes. PostgreSQL is optional
// and gets a new schema inside an explicitly supplied test database.
func dialectFixtures(t *testing.T, check func(*testing.T, *Store, string, *cryptobox.Box)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		box, err := cryptobox.New(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		dsn := "sqlite:" + filepath.Join(t.TempDir(), "database.sqlite")
		s := openDialectFixture(t, dsn, box)
		if fmt.Sprint(s.Dialect()) != "sqlite" {
			t.Fatalf("unexpected SQLite dialect: %v", s.Dialect())
		}
		check(t, s, dsn, box)
	})
	t.Run("postgres", func(t *testing.T) {
		path := os.Getenv("TEST_POSTGRES_DATABASE_DSN_FILE")
		if path == "" {
			t.Skip("requires isolated TEST_POSTGRES_DATABASE_DSN_FILE")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read PostgreSQL test DSN file")
		}
		parsed, err := url.Parse(strings.TrimSpace(string(b)))
		if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
			t.Fatal("PostgreSQL test DSN must be a postgres or postgresql URL")
		}
		box, err := cryptobox.New(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		base, err := Open(context.Background(), parsed.String(), box)
		if err != nil {
			t.Fatal(err)
		}
		id, err := ID()
		if err != nil {
			base.Close()
			t.Fatal(err)
		}
		schema := "test_dialects_" + id
		if _, err = base.DB.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
			base.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := base.DB.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
				t.Error(err)
			}
			base.Close()
		})
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		dsn := parsed.String()
		s := openDialectFixture(t, dsn, box)
		check(t, s, dsn, box)
	})
}

func openDialectFixture(t *testing.T, dsn string, box *cryptobox.Box) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := Open(ctx, dsn, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func fixtureUser(t *testing.T, s *Store, name, role string) User {
	t.Helper()
	id, err := ID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB.ExecContext(context.Background(), "INSERT INTO users(id,username,password_hash,role,enabled,preferences,created_at,updated_at) VALUES(?,?,?, ?,TRUE,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", id, name, "fixture-hash", role, []byte(`{"theme":"dark"}`))
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.User(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestDialectIdentityResourcesAndUpserts(t *testing.T) {
	dialectFixtures(t, func(t *testing.T, s *Store, _ string, _ *cryptobox.Box) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		u := fixtureUser(t, s, "member", "user")
		var preferences map[string]string
		if err := json.Unmarshal(u.Preferences, &preferences); err != nil || !u.Enabled || u.TOTPEnabled || u.CreatedAt.IsZero() || preferences["theme"] != "dark" {
			t.Fatalf("identity boolean, JSON or timestamp round trip failed: %+v", u)
		}
		account, err := s.SaveAccount(ctx, Account{Name: "fixture", Provider: "cloudflare", Config: map[string]string{"token": "private-fixture"}}, true)
		if err != nil {
			t.Fatal(err)
		}
		domain, err := s.AddDomain(ctx, Domain{AccountID: account.ID, ProviderDomainID: "1", Name: "example.test", ASCIIName: "example.test"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.AddDomain(ctx, Domain{AccountID: account.ID, ProviderDomainID: "2", Name: "example.test", ASCIIName: "example.test"})
		if !IsDuplicate(err) {
			t.Fatalf("duplicate domain was not recognized: %v", err)
		}
		if _, err = s.DB.ExecContext(ctx, "INSERT INTO domain_grants(user_id,domain_id,permissions) VALUES(?,?,?)", u.ID, domain.ID, []byte(`["dns:read","dns:write"]`)); err != nil {
			t.Fatal(err)
		}
		p := Principal{User: u}
		domains, err := s.Domains(ctx, p)
		if err != nil || len(domains) != 1 || domains[0].ID != domain.ID {
			t.Fatalf("domain grant or nested permission query failed: %v %v", domains, err)
		}
		p.Token, p.Scopes = true, []string{"dns:read"}
		allowed, err := s.CanDomain(ctx, p, domain.ID, "dns:write")
		if err != nil || allowed {
			t.Fatalf("token scope elevated domain authority: %v %v", allowed, err)
		}
		if _, err = s.DB.ExecContext(ctx, "UPDATE domains SET quicklogin_enabled=TRUE WHERE id=?", domain.ID); err != nil {
			t.Fatal(err)
		}
		token, csrf, err := s.CreateSession(ctx, u, domain.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		session, err := s.Session(ctx, token)
		if err != nil || session.CSRF != csrf || session.DomainID != domain.ID || session.Admin() {
			t.Fatalf("domain session did not retain its authority: %+v %v", session, err)
		}
		if _, err = s.DB.ExecContext(ctx, "UPDATE sessions SET expires_at=? WHERE token_hash=?", time.Now().UTC().Add(-time.Minute), cryptobox.Hash(token)); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Session(ctx, token); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("expired session was accepted: %v", err)
		}
		apiToken := "fixture-api-token"
		id, err := ID()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.DB.ExecContext(ctx, "INSERT INTO api_tokens(id,user_id,name,token_hash,scopes,created_at,expires_at) VALUES(?,?,?,?,?,UTC_TIMESTAMP(6),?)", id, u.ID, "fixture", cryptobox.Hash(apiToken), []byte(`["dns:read"]`), time.Now().UTC().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		apiPrincipal, err := s.Token(ctx, apiToken)
		if err != nil || !apiPrincipal.Token || apiPrincipal.TokenHash != cryptobox.Hash(apiToken) || apiPrincipal.AllowsScope("dns:write") {
			t.Fatalf("API token scopes did not survive JSON round trip: %+v %v", apiPrincipal, err)
		}
		if _, err = s.DB.ExecContext(ctx, "UPDATE domains SET expires_at=? WHERE id=?", time.Now().UTC().Add(time.Hour), domain.ID); err != nil {
			t.Fatal(err)
		}
		var registered, expires sql.NullTime
		if err = s.DB.QueryRowContext(ctx, "SELECT registered_at,expires_at FROM domains WHERE id=?", domain.ID).Scan(&registered, &expires); err != nil || registered.Valid || !expires.Valid {
			t.Fatalf("nullable domain timestamps did not scan: %v %v %v", registered, expires, err)
		}
		for value := 1; value <= 2; value++ {
			if err = s.SaveSetting(ctx, "fixture.setting", map[string]int{"value": value}); err != nil {
				t.Fatal(err)
			}
		}
		var setting map[string]int
		if err = s.Setting(ctx, "fixture.setting", &setting); err != nil || setting["value"] != 2 {
			t.Fatalf("setting upsert failed: %v %v", setting, err)
		}
		var version int
		if err = s.DB.QueryRowContext(ctx, "SELECT version FROM settings WHERE name=?", "fixture.setting").Scan(&version); err != nil || version != 2 {
			t.Fatalf("setting revision: %d %v", version, err)
		}
		for n := 0; n < 5; n++ {
			if err = s.LoginFailure(ctx, "fixture-attempt"); err != nil {
				t.Fatal(err)
			}
		}
		limited, err := s.LoginLimited(ctx, "fixture-attempt")
		if err != nil || !limited {
			t.Fatalf("login upsert did not count failures: %v %v", limited, err)
		}
		if _, err = s.DB.ExecContext(ctx, "UPDATE login_attempts SET expires_at=? WHERE attempt_key=?", time.Now().UTC().Add(-time.Minute), "fixture-attempt"); err != nil {
			t.Fatal(err)
		}
		if err = s.LoginFailure(ctx, "fixture-attempt"); err != nil {
			t.Fatal(err)
		}
		limited, err = s.LoginLimited(ctx, "fixture-attempt")
		if err != nil || limited {
			t.Fatalf("expired rate limit did not reset: %v %v", limited, err)
		}
		if _, err = s.DB.ExecContext(ctx, "DELETE FROM users WHERE id=?", u.ID); err != nil {
			t.Fatal(err)
		}
		var related int
		if err = s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM domain_grants WHERE user_id=?", u.ID).Scan(&related); err != nil || related != 0 {
			t.Fatalf("foreign key cascade was not enforced: %d %v", related, err)
		}
	})
}

func TestDialectConcurrentClaimsAndLeaseFencing(t *testing.T) {
	dialectFixtures(t, func(t *testing.T, s *Store, dsn string, box *cryptobox.Box) {
		peer := openDialectFixture(t, dsn, box)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		const count = 12
		for n := 0; n < count; n++ {
			if _, err := s.CreateJob(ctx, Job{Kind: "lease-fixture", OwnerID: "fixture", Payload: json.RawMessage(`{}`)}); err != nil {
				t.Fatal(err)
			}
		}
		type claim struct {
			job Job
			err error
		}
		results := make(chan claim, count)
		start := make(chan struct{})
		for n := 0; n < count; n++ {
			go func(n int) {
				<-start
				pool := s
				if n%2 == 1 {
					pool = peer
				}
				job, err := pool.ClaimJob(ctx, fmt.Sprintf("worker-%d", n), time.Minute)
				results <- claim{job, err}
			}(n)
		}
		close(start)
		seen := map[string]bool{}
		var first Job
		for n := 0; n < count; n++ {
			result := <-results
			if result.err != nil {
				t.Fatal(result.err)
			}
			if seen[result.job.ID] || result.job.Attempt != 1 || result.job.FencingToken != 1 {
				t.Fatalf("job claimed twice or fence did not advance: %+v", result.job)
			}
			seen[result.job.ID] = true
			first = result.job
		}
		if _, err := s.ClaimJob(ctx, "extra-worker", time.Minute); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("live job was reclaimed: %v", err)
		}
		if err := s.CheckpointJob(ctx, first, map[string]string{"step": "remote-accepted"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, "UPDATE jobs SET lease_until=? WHERE id=?", time.Now().UTC().Add(-time.Second), first.ID); err != nil {
			t.Fatal(err)
		}
		reclaimed, err := peer.ClaimJob(ctx, "replacement-worker", time.Minute)
		if err != nil || reclaimed.ID != first.ID || reclaimed.FencingToken != first.FencingToken+1 || string(reclaimed.Checkpoint) != `{"step":"remote-accepted"}` {
			t.Fatalf("checkpoint and fence not preserved: %+v %v", reclaimed, err)
		}
		if err = s.CompleteJob(ctx, first, "succeeded", nil, "", "", time.Time{}); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("stale worker committed completion: %v", err)
		}
		item := JobItem{Index: 0, ResourceID: "fixture", State: "running", Detail: json.RawMessage(`{"ok":true}`)}
		if err = peer.SaveJobItem(ctx, reclaimed, item); err != nil {
			t.Fatal(err)
		}
		item.State = "succeeded"
		if err = peer.SaveJobItem(ctx, reclaimed, item); err != nil {
			t.Fatal(err)
		}
		items, err := s.JobItems(ctx, reclaimed.ID)
		if err != nil || len(items) != 1 || items[0].State != "succeeded" {
			t.Fatalf("job item upsert failed: %+v %v", items, err)
		}
		if err = peer.CompleteJob(ctx, reclaimed, "succeeded", map[string]bool{"ok": true}, "", "", time.Time{}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDialectObjectRuntimeAndOutboxTransactions(t *testing.T) {
	dialectFixtures(t, func(t *testing.T, s *Store, _ string, _ *cryptobox.Box) {
		ctx := context.Background()
		o, err := s.SaveObject(ctx, Object{Kind: "monitors", Name: "fixture", OwnerID: "fixture", Active: true, Data: json.RawMessage(`{"frequency_seconds":60,"legacy":{"kept":true}}`)}, true)
		if err != nil {
			t.Fatal(err)
		}
		j, err := s.CreateJob(ctx, Job{Kind: "monitors", OwnerID: "fixture", ResourceID: o.ID, Payload: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		j, err = s.ClaimJob(ctx, "runtime-worker", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		event := map[string]string{"event": "monitor.recovery"}
		updated, err := s.SaveObjectRuntime(ctx, o, j, map[string]any{"state": map[string]bool{"healthy": true}}, "runtime-fixture", event)
		if err != nil || updated.ConfigVersion != o.ConfigVersion || updated.Version <= o.Version {
			t.Fatalf("runtime revision failed: %+v %v", updated, err)
		}
		var data map[string]any
		if err = json.Unmarshal(updated.Data, &data); err != nil || data["legacy"] == nil {
			t.Fatalf("runtime write lost configuration: %s %v", updated.Data, err)
		}
		// A repeated event must not poison its transaction on PostgreSQL.
		updated, err = s.SaveObjectRuntime(ctx, updated, j, map[string]any{"state": "still-healthy"}, "runtime-fixture", event)
		if err != nil {
			t.Fatalf("duplicate business event aborted runtime transaction: %v", err)
		}
		updated.Name = "edited fixture"
		changed, err := s.SaveObject(ctx, updated, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.SaveObject(ctx, updated, false); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale configuration version was accepted: %v", err)
		}
		if _, err = s.SaveObjectRuntime(ctx, o, j, map[string]any{"state": nil}, "stale-config", event); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale runtime configuration was accepted: %v", err)
		}
		if _, err = s.DB.ExecContext(ctx, "UPDATE jobs SET fencing_token=fencing_token+1 WHERE id=?", j.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = s.SaveObjectRuntime(ctx, changed, j, map[string]any{"state": nil}, "stale-fence", event); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("stale runtime fence was accepted: %v", err)
		}
		var count int
		if err = s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM business_events WHERE event_key IN ('stale-config','stale-fence')").Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed state update committed an event: %d %v", count, err)
		}
		broken := errors.New("fixture fanout failed")
		if err = s.DispatchOneEvent(ctx, func(json.RawMessage) ([]string, error) { return nil, broken }); !errors.Is(err, broken) {
			t.Fatal(err)
		}
		if err = s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM business_events WHERE event_key=? AND dispatched_at IS NULL", "runtime-fixture").Scan(&count); err != nil || count != 1 {
			t.Fatalf("failed dispatch lost event: %d %v", count, err)
		}
		if err = s.DispatchOneEvent(ctx, func(json.RawMessage) ([]string, error) { return []string{"channel", "channel"}, nil }); err != nil {
			t.Fatalf("duplicate channel aborted fanout transaction: %v", err)
		}
		if err = s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_outbox").Scan(&count); err != nil || count != 1 {
			t.Fatalf("notification fanout did not deduplicate: %d %v", count, err)
		}
		first, err := s.ClaimNotification(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.DB.ExecContext(ctx, "UPDATE notification_outbox SET next_run_at=? WHERE id=?", time.Now().UTC().Add(-time.Second), first.ID); err != nil {
			t.Fatal(err)
		}
		second, err := s.ClaimNotification(ctx)
		if err != nil || first.ID != second.ID || second.FencingToken <= first.FencingToken {
			t.Fatalf("notification fence did not advance: %+v %v", second, err)
		}
		if err = s.FinishNotification(ctx, first, "sent", 0); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("stale notification committed: %v", err)
		}
		if err = s.FinishNotification(ctx, second, "sent", 0); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDialectConcurrentNotificationClaimsAndBoundedRetention(t *testing.T) {
	dialectFixtures(t, func(t *testing.T, s *Store, dsn string, box *cryptobox.Box) {
		peer := openDialectFixture(t, dsn, box)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		const count = 8
		for n := 0; n < count; n++ {
			if err := s.EnqueueNotification(ctx, fmt.Sprintf("event-%d", n), "fixture-channel", map[string]int{"index": n}); err != nil {
				t.Fatal(err)
			}
		}
		type claimed struct {
			message OutboxMessage
			err     error
		}
		results := make(chan claimed, count)
		for n := 0; n < count; n++ {
			go func(n int) {
				pool := s
				if n%2 == 1 {
					pool = peer
				}
				message, err := pool.ClaimNotification(ctx)
				results <- claimed{message, err}
			}(n)
		}
		seen := map[string]bool{}
		for n := 0; n < count; n++ {
			result := <-results
			if result.err != nil {
				t.Fatal(result.err)
			}
			if seen[result.message.ID] || result.message.FencingToken != 1 {
				t.Fatalf("notification was claimed more than once: %+v", result.message)
			}
			seen[result.message.ID] = true
			if err := s.FinishNotification(ctx, result.message, "sent", 0); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.DB.ExecContext(ctx, "DELETE FROM notification_outbox WHERE state='sent' LIMIT 3"); err != nil {
			t.Fatal(err)
		}
		var remaining int
		if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_outbox").Scan(&remaining); err != nil || remaining != count-3 {
			t.Fatalf("retention did not respect its batch bound: %d %v", remaining, err)
		}
		kept, err := s.CreateJob(ctx, Job{Kind: "retention", OwnerID: "fixture", Payload: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		removed, err := s.CreateJob(ctx, Job{Kind: "retention", OwnerID: "fixture", Payload: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.DB.ExecContext(ctx, "UPDATE jobs SET state='succeeded',updated_at=? WHERE id IN (?,?)", time.Now().UTC().AddDate(-1, 0, 0), kept.ID, removed.ID); err != nil {
			t.Fatal(err)
		}
		if err = s.QueueBusinessEvent(ctx, "job:"+kept.ID, map[string]string{"event": "keep"}); err != nil {
			t.Fatal(err)
		}
		query := "DELETE FROM jobs WHERE state IN ('succeeded','failed','cancelled','partial') AND updated_at<? AND NOT EXISTS(SELECT 1 FROM business_events b WHERE b.event_key LIKE CONCAT('%',jobs.id,'%') AND b.dispatched_at IS NULL) LIMIT 100"
		if _, err = s.DB.ExecContext(ctx, query, time.Now().UTC().AddDate(0, 0, -90)); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Job(ctx, kept.ID); err != nil {
			t.Fatalf("retention removed unpublished event evidence: %v", err)
		}
		if _, err = s.Job(ctx, removed.ID); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("retention retained obsolete completed job: %v", err)
		}
	})
}

func TestDialectResourceLocksAcrossPools(t *testing.T) {
	dialectFixtures(t, func(t *testing.T, s *Store, dsn string, box *cryptobox.Box) {
		peer := openDialectFixture(t, dsn, box)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		keys := []string{"z:fixture", "a:fixture", "a:fixture"}
		release, err := s.LockResources(ctx, keys)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if keys[0] != "z:fixture" {
			t.Fatal("resource locking changed caller keys")
		}
		if err = s.DB.PingContext(ctx); err != nil {
			t.Fatalf("resource locks exhausted the normal pool: %v", err)
		}
		if _, err = peer.LockResources(ctx, []string{"0:fixture", "a:fixture"}); !errors.Is(err, ErrResourceBusy) {
			t.Fatalf("second pool acquired a held resource: %v", err)
		}
		// A partial failed acquisition must release its other resource.
		unrelated, err := peer.LockResources(ctx, []string{"0:fixture"})
		if err != nil {
			t.Fatalf("failed acquisition leaked a resource lock: %v", err)
		}
		unrelated()
		release()
		again, err := peer.LockResources(ctx, keys)
		if err != nil {
			t.Fatalf("released resource remained locked: %v", err)
		}
		again()
	})
}

func TestSQLiteResourceLocksAcrossProcesses(t *testing.T) {
	box, err := cryptobox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	dsn := "sqlite:" + filepath.Join(t.TempDir(), "database.sqlite")
	s := openDialectFixture(t, dsn, box)
	release, err := s.LockResources(context.Background(), []string{"process-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSQLiteResourceLockProcessHelper$", "-test.count=1")
		cmd.Env = append(os.Environ(), "DNSMGR_TEST_SQLITE_LOCK_DSN="+dsn, "DNSMGR_TEST_SQLITE_LOCK_MODE="+mode)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("resource lock subprocess: %v\n%s", err, output)
		}
	}
	run("busy")
	release()
	run("available")
	run("exit")
	acquired, err := s.LockResources(context.Background(), []string{"process-fixture"})
	if err != nil {
		t.Fatalf("exited process retained a resource lock: %v", err)
	}
	acquired()
}

func TestSQLiteResourceLockProcessHelper(t *testing.T) {
	dsn := os.Getenv("DNSMGR_TEST_SQLITE_LOCK_DSN")
	if dsn == "" {
		t.Skip("only runs as a lock test subprocess")
	}
	box, err := cryptobox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := Open(ctx, dsn, box)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	release, err := s.LockResources(ctx, []string{"process-fixture"})
	if os.Getenv("DNSMGR_TEST_SQLITE_LOCK_MODE") == "busy" {
		if !errors.Is(err, ErrResourceBusy) {
			if release != nil {
				release()
			}
			t.Fatalf("another process acquired the held lock: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DNSMGR_TEST_SQLITE_LOCK_MODE") == "exit" {
		os.Exit(0) // Verify the OS drops the lock without a deferred release.
	}
	release()
}

func TestDialectInstallSerializesAndMigrationIsRepeatable(t *testing.T) {
	dialectFixtures(t, func(t *testing.T, s *Store, dsn string, box *cryptobox.Box) {
		peer := openDialectFixture(t, dsn, box)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, pool := range []*Store{s, peer} {
			wg.Add(1)
			go func(pool *Store) {
				defer wg.Done()
				_, err := pool.Install(ctx, "administrator", "test-password-strong-enough")
				results <- err
			}(pool)
		}
		wg.Wait()
		close(results)
		succeeded, conflicted := 0, 0
		for err := range results {
			if err == nil {
				succeeded++
			} else if errors.Is(err, ErrConflict) {
				conflicted++
			} else {
				t.Fatal(err)
			}
		}
		if succeeded != 1 || conflicted != 1 {
			t.Fatalf("initial installation raced: successes=%d conflicts=%d", succeeded, conflicted)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("repeat migration failed: %v", err)
		}
		var count int
		if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil || count != 1 {
			t.Fatalf("installation produced multiple administrators: %d %v", count, err)
		}
	})
}
