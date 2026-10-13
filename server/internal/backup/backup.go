// Package backup captures and restores the complete Go database. Provider
// credentials and private keys remain encrypted inside an authenticated archive.
package backup

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/database"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

const MaxArchiveBytes int64 = 1 << 30

var safeName = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// The complete current schema is explicit so an unrelated table cannot silently
// be published in a backup, and future schema changes cannot omit new data.
// Historical compatibility tables remain included for complete restoration.
var Tables = []string{"users", "domain_grants", "sessions", "api_tokens", "provider_accounts", "domains", "objects", "jobs", "job_events", "audit_events", "settings", "login_attempts", "owner_registry", "migration_imports", "job_items", "worker_heartbeats", "notification_outbox", "login_tickets", "object_schedule_state", "legacy_identities", "legacy_resources", "migration_manifests", "legacy_id_map", "legacy_api_credentials", "migration_archives", "business_events", "dns_challenge_intents", "goose_db_version"}

type Column struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Nullable bool    `json:"nullable"`
	Default  *string `json:"default"`
	Extra    string  `json:"extra"`
}
type ForeignKey struct {
	Column           string `json:"column"`
	Table            string `json:"table"`
	ReferencedColumn string `json:"referenced_column"`
	OnUpdate         string `json:"on_update,omitempty"`
	OnDelete         string `json:"on_delete,omitempty"`
	Match            string `json:"match,omitempty"`
}
type Definition struct {
	Name        string       `json:"name"`
	Columns     []Column     `json:"columns"`
	PrimaryKey  []string     `json:"primary_key"`
	ForeignKeys []ForeignKey `json:"foreign_keys"`
}
type Cell struct {
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}
type TableData struct {
	Definition Definition `json:"definition"`
	Rows       [][]Cell   `json:"rows"`
}
type Snapshot struct {
	Version       int         `json:"version"`
	ID            string      `json:"id"`
	CapturedAt    time.Time   `json:"captured_at"`
	Timezone      string      `json:"timezone"`
	Dialect       string      `json:"dialect,omitempty"`
	SchemaVersion int64       `json:"schema_version"`
	Tables        []TableData `json:"tables"`
}
type Archive struct {
	Version    int    `json:"version"`
	ID         string `json:"id"`
	Ciphertext string `json:"ciphertext"`
}
type Report struct {
	ID            string         `json:"backup_id"`
	SchemaVersion int64          `json:"schema_version"`
	Counts        map[string]int `json:"counts"`
	CapturedAt    time.Time      `json:"captured_at"`
	Restored      bool           `json:"restored"`
	DryRun        bool           `json:"dry_run"`
}
type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func mysqlSchema(ctx context.Context, q queryer) ([]Definition, int64, error) {
	rows, err := q.QueryContext(ctx, "SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")
	if err != nil {
		return nil, 0, errors.New("cannot inspect database schema")
	}
	allowed := map[string]bool{}
	for _, name := range Tables {
		allowed[name] = true
	}
	names := []string{}
	for rows.Next() {
		var name, engine string
		if err = rows.Scan(&name, &engine); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if !allowed[name] || !safeName.MatchString(name) || engine != "InnoDB" {
			rows.Close()
			return nil, 0, errors.New("database contains an unknown or nontransactional table")
		}
		names = append(names, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	if len(names) != len(Tables) {
		return nil, 0, errors.New("database schema is incomplete; run the shipped migrations first")
	}
	definitions := []Definition{}
	for _, name := range names {
		d := Definition{Name: name, Columns: []Column{}, PrimaryKey: []string{}, ForeignKeys: []ForeignKey{}}
		cols, e := q.QueryContext(ctx, "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION", name)
		if e != nil {
			return nil, 0, e
		}
		for cols.Next() {
			var c Column
			var nullable string
			var defaultValue sql.NullString
			if e = cols.Scan(&c.Name, &c.Type, &nullable, &defaultValue, &c.Extra); e != nil {
				cols.Close()
				return nil, 0, e
			}
			if !safeName.MatchString(c.Name) {
				cols.Close()
				return nil, 0, errors.New("unsafe schema column")
			}
			c.Nullable = nullable == "YES"
			if defaultValue.Valid {
				value := defaultValue.String
				c.Default = &value
			}
			d.Columns = append(d.Columns, c)
		}
		e = cols.Err()
		cols.Close()
		if e != nil {
			return nil, 0, e
		}
		constraints, e := q.QueryContext(ctx, "SELECT COLUMN_NAME,CONSTRAINT_NAME,COALESCE(REFERENCED_TABLE_NAME,''),COALESCE(REFERENCED_COLUMN_NAME,'') FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY CONSTRAINT_NAME,ORDINAL_POSITION", name)
		if e != nil {
			return nil, 0, e
		}
		for constraints.Next() {
			var col, key, referenced, refcol string
			if e = constraints.Scan(&col, &key, &referenced, &refcol); e != nil {
				constraints.Close()
				return nil, 0, e
			}
			if key == "PRIMARY" {
				d.PrimaryKey = append(d.PrimaryKey, col)
			}
			if referenced != "" {
				d.ForeignKeys = append(d.ForeignKeys, ForeignKey{Column: col, Table: referenced, ReferencedColumn: refcol})
			}
		}
		e = constraints.Err()
		constraints.Close()
		if e != nil {
			return nil, 0, e
		}
		definitions = append(definitions, d)
	}
	var version int64
	if err = q.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_id),0) FROM goose_db_version WHERE is_applied=TRUE").Scan(&version); err != nil {
		return nil, 0, err
	}
	return definitions, version, nil
}
func Capture(ctx context.Context, s *store.Store, frozen bool) (Snapshot, Report, error) {
	report := Report{Counts: map[string]int{}}
	if !frozen {
		return Snapshot{}, report, errors.New("backup requires --go-frozen after stopping Go API writes and workers")
	}
	release, err := s.LockSchema(ctx, 5*time.Second)
	if err != nil {
		return Snapshot{}, report, err
	}
	defer release()
	options := &sql.TxOptions{ReadOnly: true}
	if s.Dialect() != database.SQLite {
		options.Isolation = sql.LevelRepeatableRead
	}
	tx, err := s.DB.BeginTx(ctx, options)
	if err != nil {
		return Snapshot{}, report, err
	}
	defer tx.Rollback()
	definitions, version, err := schema(ctx, tx, s.Dialect())
	if err != nil {
		return Snapshot{}, report, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM jobs WHERE state='running'").Scan(&active); err != nil {
		return Snapshot{}, report, err
	}
	if active > 0 {
		return Snapshot{}, report, errors.New("running jobs must stop and release their leases before backup")
	}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_outbox WHERE state IN ('sending','running')").Scan(&active); err != nil {
		return Snapshot{}, report, err
	}
	if active > 0 {
		return Snapshot{}, report, errors.New("in-flight notification delivery must be reconciled before backup")
	}
	id, err := store.ID()
	if err != nil {
		return Snapshot{}, report, err
	}
	snapshot := Snapshot{Version: 1, ID: id, CapturedAt: time.Now().UTC(), Timezone: "UTC", Dialect: string(s.Dialect()), SchemaVersion: version, Tables: []TableData{}}
	for _, d := range definitions {
		data, e := captureTable(ctx, tx, d, s.Dialect())
		if e != nil {
			return snapshot, report, fmt.Errorf("cannot capture table %s: %w", d.Name, e)
		}
		if e = validateCiphertexts(s.Box, data); e != nil {
			return snapshot, report, e
		}
		snapshot.Tables = append(snapshot.Tables, data)
		report.Counts[d.Name] = len(data.Rows)
	}
	if err = tx.Commit(); err != nil {
		return snapshot, report, err
	}
	report.ID, report.SchemaVersion, report.CapturedAt = snapshot.ID, version, snapshot.CapturedAt
	return snapshot, report, nil
}
func captureTable(ctx context.Context, q queryer, d Definition, dialects ...database.Dialect) (TableData, error) {
	out := TableData{Definition: d, Rows: [][]Cell{}}
	dialect := database.MySQL
	if len(dialects) > 0 {
		dialect = dialects[0]
	}
	query := "SELECT * FROM " + quote(dialect, d.Name)
	if len(d.PrimaryKey) > 0 {
		names := []string{}
		for _, name := range d.PrimaryKey {
			names = append(names, quote(dialect, name))
		}
		query += " ORDER BY " + strings.Join(names, ",")
	}
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil || len(columns) != len(d.Columns) {
		return out, errors.New("table columns changed")
	}
	for i, name := range columns {
		if name != d.Columns[i].Name {
			return out, errors.New("table column order changed")
		}
	}
	for rows.Next() {
		values, ptrs := make([]any, len(columns)), make([]any, len(columns))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err = rows.Scan(ptrs...); err != nil {
			return out, err
		}
		cells := make([]Cell, len(columns))
		for i, v := range values {
			switch value := v.(type) {
			case nil:
				cells[i] = Cell{Kind: "null"}
			case []byte:
				cells[i] = Cell{Kind: "bytes", Value: base64.StdEncoding.EncodeToString(value)}
			case time.Time:
				cells[i] = Cell{Kind: "time", Value: value.UTC().Format(time.RFC3339Nano)}
			case string:
				cells[i] = Cell{Kind: "text", Value: value}
			case int64:
				cells[i] = Cell{Kind: "integer", Value: strconv.FormatInt(value, 10)}
			case uint64:
				cells[i] = Cell{Kind: "unsigned", Value: strconv.FormatUint(value, 10)}
			case float64:
				cells[i] = Cell{Kind: "number", Value: strconv.FormatFloat(value, 'g', -1, 64)}
			case bool:
				cells[i] = Cell{Kind: "boolean", Value: strconv.FormatBool(value)}
			default:
				return out, errors.New("unsupported database value")
			}
		}
		out.Rows = append(out.Rows, cells)
	}
	return out, rows.Err()
}
func Write(path string, box *cryptobox.Box, snapshot Snapshot) error {
	if err := validate(snapshot); err != nil {
		return err
	}
	plain, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if int64(len(plain)) > MaxArchiveBytes*3/4 {
		return errors.New("backup exceeds archive size limit")
	}
	ciphertext, err := box.Seal("go-backup:"+snapshot.ID, plain)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(Archive{Version: 1, ID: snapshot.ID, Ciphertext: ciphertext})
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("backup destination must be a new writable file")
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = file.Write(raw); err != nil {
		return errors.New("cannot write backup archive")
	}
	if err = file.Sync(); err != nil {
		return errors.New("cannot sync backup archive")
	}
	ok = true
	return nil
}
func Read(path string, box *cryptobox.Box) (Snapshot, error) {
	stat, err := os.Stat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > MaxArchiveBytes {
		return Snapshot{}, errors.New("backup must be a regular file within the size limit")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, errors.New("cannot read backup archive")
	}
	var archive Archive
	if json.Unmarshal(raw, &archive) != nil || archive.Version != 1 || archive.ID == "" {
		return Snapshot{}, errors.New("invalid backup archive")
	}
	plain, err := box.Open("go-backup:"+archive.ID, archive.Ciphertext)
	if err != nil {
		return Snapshot{}, errors.New("backup authentication failed; provide the original master key")
	}
	var snapshot Snapshot
	if json.Unmarshal(plain, &snapshot) != nil || snapshot.ID != archive.ID {
		return Snapshot{}, errors.New("invalid backup snapshot")
	}
	if err = validate(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}
func validate(snapshot Snapshot) error {
	if snapshot.Version != 1 || snapshot.ID == "" || snapshot.CapturedAt.IsZero() || snapshot.Timezone != "UTC" || snapshot.SchemaVersion < 1 || len(snapshot.Tables) != len(Tables) {
		return errors.New("invalid backup manifest or schema version")
	}
	if snapshot.Dialect != "" && snapshot.Dialect != string(database.MySQL) && snapshot.Dialect != string(database.PostgreSQL) && snapshot.Dialect != string(database.SQLite) {
		return errors.New("unsupported backup database dialect")
	}
	allowed := map[string]bool{}
	for _, name := range Tables {
		allowed[name] = true
	}
	seen := map[string]bool{}
	columns := map[string]map[string]bool{}
	for _, data := range snapshot.Tables {
		name := data.Definition.Name
		if !allowed[name] || seen[name] || !safeName.MatchString(name) || len(data.Definition.Columns) == 0 {
			return errors.New("backup table manifest is incomplete or duplicated")
		}
		seen[name] = true
		columns[name] = map[string]bool{}
		for _, column := range data.Definition.Columns {
			if !safeName.MatchString(column.Name) || columns[name][column.Name] || strings.Contains(strings.ToLower(column.Extra), "virtual generated") || strings.Contains(strings.ToLower(column.Extra), "stored generated") {
				return errors.New("backup contains unsupported schema columns")
			}
			columns[name][column.Name] = true
		}
		for _, row := range data.Rows {
			if len(row) != len(data.Definition.Columns) {
				return errors.New("backup row has invalid column count")
			}
			for _, cell := range row {
				if _, err := decodeCell(cell); err != nil {
					return err
				}
			}
		}
	}
	for _, data := range snapshot.Tables {
		primary := map[string]bool{}
		for _, column := range data.Definition.PrimaryKey {
			if !columns[data.Definition.Name][column] || primary[column] {
				return errors.New("backup primary-key definition is invalid")
			}
			primary[column] = true
		}
		for _, fk := range data.Definition.ForeignKeys {
			if !columns[data.Definition.Name][fk.Column] || !columns[fk.Table][fk.ReferencedColumn] {
				return errors.New("backup foreign-key definition is invalid")
			}
		}
	}
	return nil
}
func decodeCell(c Cell) (any, error) {
	switch c.Kind {
	case "null":
		if c.Value != "" {
			return nil, errors.New("invalid NULL backup value")
		}
		return nil, nil
	case "bytes":
		return base64.StdEncoding.DecodeString(c.Value)
	case "text":
		return c.Value, nil
	case "time":
		t, err := time.Parse(time.RFC3339Nano, c.Value)
		if err != nil {
			return nil, errors.New("invalid UTC backup date")
		}
		return t.UTC(), nil
	case "integer":
		v, err := strconv.ParseInt(c.Value, 10, 64)
		if err != nil {
			return nil, errors.New("invalid backup integer")
		}
		return v, nil
	case "number":
		v, err := strconv.ParseFloat(c.Value, 64)
		if err != nil {
			return nil, errors.New("invalid backup number")
		}
		return v, nil
	case "unsigned":
		v, err := strconv.ParseUint(c.Value, 10, 64)
		if err != nil {
			return nil, errors.New("invalid backup unsigned integer")
		}
		return v, nil
	case "boolean":
		return strconv.ParseBool(c.Value)
	}
	return nil, errors.New("invalid backup value encoding")
}
func cellText(c Cell) string {
	value, err := decodeCell(c)
	if err != nil || value == nil {
		return ""
	}
	if b, ok := value.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(value)
}
func insertionOrder(tables []TableData) ([]TableData, error) {
	pending := map[string]TableData{}
	for _, t := range tables {
		pending[t.Definition.Name] = t
	}
	out, done := []TableData{}, map[string]bool{}
	for len(pending) > 0 {
		names := []string{}
		for name := range pending {
			names = append(names, name)
		}
		sort.Strings(names)
		progress := false
		for _, name := range names {
			table := pending[name]
			ready := true
			for _, fk := range table.Definition.ForeignKeys {
				if fk.Table != name && !done[fk.Table] {
					ready = false
				}
			}
			if ready {
				out = append(out, table)
				done[name] = true
				delete(pending, name)
				progress = true
			}
		}
		if !progress {
			return nil, errors.New("backup foreign-key dependency graph is cyclic or incomplete")
		}
	}
	return out, nil
}
