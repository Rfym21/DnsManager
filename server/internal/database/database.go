// Package database adapts the repository's SQL to its supported databases.
package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
	"modernc.org/sqlite"
)

// Dialect identifies the database SQL implementation.
type Dialect string

const (
	MySQL      Dialect = "mysql"
	PostgreSQL Dialect = "postgres"
	SQLite     Dialect = "sqlite"
)

// DB preserves database/sql's pool API while adapting application statements.
type DB struct {
	*sql.DB
	dialect Dialect
	name    string
	lockDir string
}

// Open accepts a MySQL DSN, a postgres:// URL or sqlite:/path/to/database.db.
func Open(ctx context.Context, dsn string) (*DB, error) {
	d := &DB{}
	lower := strings.ToLower(dsn)
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		d.dialect = PostgreSQL
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			return nil, errors.New("invalid PostgreSQL connection URL")
		}
		cfg.ConnectTimeout = 5 * time.Second
		cfg.RuntimeParams["timezone"] = "UTC"
		d.name = cfg.Database
		d.DB = stdlib.OpenDB(*cfg, stdlib.OptionAfterConnect(func(ctx context.Context, c *pgx.Conn) error {
			c.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID, Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC}})
			return nil
		}))
	case strings.HasPrefix(lower, "sqlite:"):
		d.dialect = SQLite
		path := dsn[len("sqlite:"):]
		if strings.HasPrefix(path, "//") || strings.HasPrefix(path, `\\`) {
			return nil, errors.New("SQLite requires a local file path, without a network or URI authority")
		}
		if path == "" {
			return nil, errors.New("SQLite database path is required")
		}
		if path == ":memory:" {
			return nil, errors.New("SQLite requires a file path so API and Worker share data and locks")
		}
		absolute, err := filepath.Abs(filepath.FromSlash(path))
		if err != nil {
			return nil, errors.New("invalid SQLite database path")
		}
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		}
		if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
			return nil, errors.New("cannot create SQLite database directory")
		}
		f, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, errors.New("cannot open SQLite database file")
		}
		if err = f.Close(); err != nil {
			return nil, errors.New("cannot close SQLite database file")
		}
		// Resolve after creation too: a new file inside a symlinked directory
		// must use the same lock directory as later opens through its real path.
		absolute, err = filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, errors.New("cannot resolve SQLite database file")
		}
		d.name, d.lockDir = absolute, absolute+".locks"
		if err = os.MkdirAll(d.lockDir, 0700); err != nil {
			return nil, errors.New("cannot create SQLite lock directory")
		}
		uriPath := filepath.ToSlash(absolute)
		if !strings.HasPrefix(uriPath, "/") {
			uriPath = "/" + uriPath
		}
		u := url.URL{Scheme: "file", Path: uriPath}
		q := url.Values{"_pragma": {"busy_timeout(10000)", "foreign_keys(1)", "journal_mode(WAL)"}, "_txlock": {"immediate"}, "_texttotime": {"1"}}
		u.RawQuery = q.Encode()
		d.DB, err = sql.Open("sqlite", u.String())
		if err != nil {
			return nil, errors.New("cannot open SQLite database")
		}
	default:
		d.dialect = MySQL
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			return nil, errors.New("invalid MySQL database DSN")
		}
		cfg.ParseTime, cfg.Loc = true, time.UTC
		if cfg.Params == nil {
			cfg.Params = map[string]string{}
		}
		cfg.Params["time_zone"] = "'+00:00'"
		cfg.Collation = "utf8mb4_unicode_ci"
		cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
		d.name = cfg.DBName
		d.DB, err = sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			return nil, errors.New("cannot open MySQL database")
		}
	}
	d.SetMaxOpenConns(20)
	d.SetMaxIdleConns(5)
	d.SetConnMaxLifetime(5 * time.Minute)
	if err := d.PingContext(ctx); err != nil {
		d.Close()
		return nil, errors.New("database connection failed")
	}
	return d, nil
}

// Raw returns the native connection pool for schema tools.
func (d *DB) Raw() *sql.DB { return d.DB }

// Dialect returns the selected SQL implementation.
func (d *DB) Dialect() Dialect { return d.dialect }

// Name returns the database name or canonical SQLite file path.
func (d *DB) Name() string { return d.name }

// LockDir returns the SQLite lock directory.
func (d *DB) LockDir() string { return d.lockDir }

func arguments(dialect Dialect, args []any) []any {
	if dialect == MySQL {
		return args
	}
	result := append([]any(nil), args...)
	for i, v := range result {
		switch v := v.(type) {
		case []byte:
			result[i] = string(v)
		case json.RawMessage:
			result[i] = string(v)
		case time.Time:
			if dialect == SQLite {
				result[i] = v.UTC().Format("2006-01-02 15:04:05.000000000")
			} else {
				result[i] = v.UTC()
			}
		case *time.Time:
			if v == nil {
				result[i] = nil
			} else {
				result[i] = arguments(dialect, []any{*v})[0]
			}
		case driver.Valuer:
			if value, err := v.Value(); err == nil {
				result[i] = arguments(dialect, []any{value})[0]
			}
		}
	}
	return result
}

func (d *DB) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, Rewrite(d.dialect, q), arguments(d.dialect, args)...)
}
func (d *DB) Exec(q string, args ...any) (sql.Result, error) {
	return d.ExecContext(context.Background(), q, args...)
}
func (d *DB) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, Rewrite(d.dialect, q), arguments(d.dialect, args)...)
}
func (d *DB) Query(q string, args ...any) (*sql.Rows, error) {
	return d.QueryContext(context.Background(), q, args...)
}
func (d *DB) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, Rewrite(d.dialect, q), arguments(d.dialect, args)...)
}
func (d *DB) QueryRow(q string, args ...any) *sql.Row {
	return d.QueryRowContext(context.Background(), q, args...)
}

// Tx adapts statements without changing transaction boundaries.
type Tx struct {
	*sql.Tx
	dialect Dialect
}

func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, e := d.DB.BeginTx(ctx, opts)
	if e != nil {
		return nil, e
	}
	return &Tx{tx, d.dialect}, nil
}
func (t *Tx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, Rewrite(t.dialect, q), arguments(t.dialect, args)...)
}
func (t *Tx) Exec(q string, args ...any) (sql.Result, error) {
	return t.ExecContext(context.Background(), q, args...)
}
func (t *Tx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, Rewrite(t.dialect, q), arguments(t.dialect, args)...)
}
func (t *Tx) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, Rewrite(t.dialect, q), arguments(t.dialect, args)...)
}

// Conn retains session affinity for PostgreSQL and MySQL advisory locks.
type Conn struct {
	*sql.Conn
	dialect Dialect
}

func (d *DB) Conn(ctx context.Context) (*Conn, error) {
	c, e := d.DB.Conn(ctx)
	if e != nil {
		return nil, e
	}
	return &Conn{c, d.dialect}, nil
}
func (c *Conn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return c.Conn.ExecContext(ctx, Rewrite(c.dialect, q), arguments(c.dialect, args)...)
}
func (c *Conn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return c.Conn.QueryContext(ctx, Rewrite(c.dialect, q), arguments(c.dialect, args)...)
}
func (c *Conn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return c.Conn.QueryRowContext(ctx, Rewrite(c.dialect, q), arguments(c.dialect, args)...)
}

// IsDuplicate reports unique constraint violations across supported databases.
func IsDuplicate(err error) bool {
	var m *mysql.MySQLError
	var p *pgconn.PgError
	var s *sqlite.Error
	return errors.As(err, &m) && m.Number == 1062 || errors.As(err, &p) && p.Code == "23505" || errors.As(err, &s) && (s.Code() == 1555 || s.Code() == 2067)
}
