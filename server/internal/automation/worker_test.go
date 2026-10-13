package automation

import (
	"context"
	"encoding/json"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func workerStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if p := os.Getenv("TEST_DATABASE_DSN_FILE"); p != "" {
		raw, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		dsn = strings.TrimSpace(string(raw))
	}
	if dsn == "" {
		dsn = "sqlite:" + filepath.Join(t.TempDir(), "worker.sqlite")
	}
	box, _ := cryptobox.New(make([]byte, 32))
	s, e := store.Open(context.Background(), dsn, box)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if e = s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	return s
}
func workerUser(t *testing.T, s *store.Store) store.User {
	id, _ := store.ID()
	_, e := s.DB.Exec("INSERT INTO users(id,username,password_hash,role,enabled,preferences,created_at,updated_at) VALUES(?,?,'fixture','admin',TRUE,'{}',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", id, id)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM jobs WHERE owner_id=?", id)
		s.DB.Exec("DELETE FROM users WHERE id=?", id)
	})
	u, e := s.User(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	return u
}
func TestWorkerExecutesDNSBatchWithDurableItemAndSubmission(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	var mu sync.Mutex
	var sets []map[string]any
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "fixture-key" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "PATCH" {
			var body struct {
				Sets []map[string]any `json:"rrsets"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			sets = body.Sets
			w.WriteHeader(204)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"rrsets": sets})
	}))
	defer remote.Close()
	a, e := s.SaveAccount(ctx, store.Account{Name: "PowerDNS fixture", Provider: "powerdns", Config: map[string]string{"url": remote.URL, "apikey": "fixture-key"}}, true)
	if e != nil {
		t.Fatal(e)
	}
	d, e := s.AddDomain(ctx, store.Domain{AccountID: a.ID, Name: "example.invalid", ASCIIName: "example.invalid", ProviderDomainID: "example.invalid."})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		s.DB.Exec("DELETE FROM domains WHERE id=?", d.ID)
		s.DB.Exec("DELETE FROM provider_accounts WHERE id=?", a.ID)
	})
	payload := json.RawMessage(`{"domain_ids":["` + d.ID + `"],"operation":"create","records":[{"name":"www","type":"A","value":"192.0.2.10","ttl":300,"enabled":true}]}`)
	p := store.Principal{User: u}
	job, e := s.CreateJob(ctx, store.Job{Kind: "record_batch", OwnerID: u.ID, DomainID: d.ID, Payload: payload, Total: 1, Submission: store.Submission(p)})
	if e != nil {
		t.Fatal(e)
	}
	claimed, e := s.ClaimJob(ctx, "fixture-worker", 30*time.Second)
	if e != nil || claimed.ID != job.ID {
		t.Fatal("claim", e)
	}
	w := Worker{Store: s, Lease: 30 * time.Second, Handlers: (&Runner{Store: s}).Handlers()}
	w.execute(ctx, claimed)
	result, e := s.Job(ctx, job.ID)
	if e != nil || result.State != "succeeded" || result.Completed != 1 {
		t.Fatalf("batch state=%s completed=%d error=%s err=%v", result.State, result.Completed, result.ErrorMessage, e)
	}
	items, e := s.JobItems(ctx, job.ID)
	if e != nil || len(items) != 1 || items[0].State != "succeeded" {
		t.Fatal("durable result absent", e)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sets) != 1 || sets[0]["name"] != "www.example.invalid." {
		t.Fatal("remote write missing")
	}
}
func TestWorkerCancellationAndPanicRemainDurable(t *testing.T) {
	s := workerStore(t)
	u := workerUser(t, s)
	ctx := context.Background()
	for _, kind := range []string{"cancel_fixture", "panic_fixture"} {
		j, e := s.CreateJob(ctx, store.Job{Kind: kind, OwnerID: u.ID, Payload: []byte("{}")})
		if e != nil {
			t.Fatal(e)
		}
		claimed, e := s.ClaimJob(ctx, "worker", 30*time.Second)
		if e != nil || claimed.ID != j.ID {
			t.Fatal(e)
		}
		w := Worker{Store: s, Lease: 30 * time.Second, Handlers: map[string]Handler{kind: func(ctx context.Context, j store.Job) (any, error) {
			if kind == "panic_fixture" {
				panic("secret panic must not be exposed")
			}
			if e := s.CancelJob(ctx, j.ID); e != nil {
				return nil, e
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}}}
		w.execute(ctx, claimed)
		result, e := s.Job(ctx, j.ID)
		if e != nil {
			t.Fatal(e)
		}
		expected := "cancelled"
		if kind == "panic_fixture" {
			expected = "unknown"
		}
		if result.State != expected {
			t.Fatalf("expected %s got %s", expected, result.State)
		}
		if strings.Contains(result.ErrorMessage, "secret") {
			t.Fatal("panic detail leaked")
		}
	}
}
