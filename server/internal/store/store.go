package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/database"
	"github.com/dns-manager/dnsmgr/server/internal/redaction"
	"github.com/dns-manager/dnsmgr/server/migrations"
	"github.com/pressly/goose/v3"
)

type Store struct {
	DB     *database.DB
	LockDB *database.DB
	Box    *cryptobox.Box
}

func (s *Store) Close() error {
	if s.LockDB != nil {
		s.LockDB.Close()
	}
	return s.DB.Close()
}

func Open(ctx context.Context, dsn string, box *cryptobox.Box) (*Store, error) {
	db, err := database.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	// Long remote jobs hold session locks. A separate pool keeps those sessions
	// from exhausting the normal pool needed for leases and completion writes.
	locks, err := database.Open(ctx, dsn)
	if err != nil {
		db.Close()
		return nil, errors.New("cannot open lock connection pool")
	}
	locks.SetMaxOpenConns(64)
	locks.SetMaxIdleConns(5)
	locks.SetConnMaxIdleTime(time.Minute)
	return &Store{DB: db, LockDB: locks, Box: box}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	release, err := s.LockSchema(ctx, 30*time.Second)
	if err != nil {
		return err
	}
	defer release()
	files, err := migrations.FilesFor(string(s.Dialect()))
	if err != nil {
		return err
	}
	dialect := goose.DialectMySQL
	if s.Dialect() == database.PostgreSQL {
		dialect = goose.DialectPostgres
	}
	if s.Dialect() == database.SQLite {
		dialect = goose.DialectSQLite3
	}
	provider, err := goose.NewProvider(dialect, s.DB.Raw(), files)
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}

func ID() (string, error) { return cryptobox.RandomHex(16) }

func (s *Store) Encrypt(scope string, data any) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return s.Box.Seal(scope, b)
}

func (s *Store) Decrypt(scope, ciphertext string, target any) error {
	b, err := s.Box.Open(scope, ciphertext)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, target)
}

func (s *Store) Audit(ctx context.Context, actor, action, kind, resource, domain, requestID string, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO audit_events (actor_id,action,resource_type,resource_id,domain_id,request_id,detail,created_at) VALUES (?,?,?,?,?,?,?,UTC_TIMESTAMP(6))", actor, action, kind, resource, nullString(domain), requestID, []byte(redaction.JSON(b)))
	return err
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func IsDuplicate(err error) bool {
	return database.IsDuplicate(err)
}

// Dialect identifies the selected storage engine.
func (s *Store) Dialect() database.Dialect { return s.DB.Dialect() }

// DatabaseName returns the current database's name or SQLite file path.
func (s *Store) DatabaseName(ctx context.Context) (string, error) { return s.DB.Name(), ctx.Err() }

// LockSchema coordinates schema upgrades and full backup operations.
func (s *Store) LockSchema(ctx context.Context, timeout time.Duration) (func(), error) {
	pool := s.LockDB
	if pool == nil {
		pool = s.DB
	}
	return pool.Lock(ctx, []string{"@schema"}, timeout)
}

func (s *Store) Setting(ctx context.Context, name string, target any) error {
	var ciphertext string
	if err := s.DB.QueryRowContext(ctx, "SELECT ciphertext FROM settings WHERE name=?", name).Scan(&ciphertext); err != nil {
		return err
	}
	return s.Decrypt("setting:"+name, ciphertext, target)
}

func (s *Store) SaveSetting(ctx context.Context, name string, value any) error {
	ciphertext, err := s.Encrypt("setting:"+name, value)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "INSERT INTO settings (name,ciphertext,updated_at) VALUES (?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE ciphertext=VALUES(ciphertext),version=version+1,updated_at=UTC_TIMESTAMP(6)", name, ciphertext)
	return err
}
