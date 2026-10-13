package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/database"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

// Restore requires the same shipped schema and an empty application database.
// Existing goose schema history is checked rather than replaced. FK checks stay
// enabled and every application row is inserted in one transaction.
func Restore(ctx context.Context, s *store.Store, snapshot Snapshot, frozen, dry bool) (Report, error) {
	report := Report{ID: snapshot.ID, SchemaVersion: snapshot.SchemaVersion, CapturedAt: snapshot.CapturedAt, Counts: map[string]int{}, DryRun: dry}
	if !frozen {
		return report, errors.New("restore requires --go-frozen and an empty target database")
	}
	if err := validate(snapshot); err != nil {
		return report, err
	}
	dialect := snapshot.Dialect
	if dialect == "" {
		// Archives created before database dialects were introduced are MySQL.
		dialect = string(database.MySQL)
	}
	if dialect != string(s.Dialect()) {
		return report, errors.New("backup database dialect differs from target; restore to the original database engine")
	}
	for _, data := range snapshot.Tables {
		if err := validateCiphertexts(s.Box, data); err != nil {
			return report, err
		}
	}
	release, err := s.LockSchema(ctx, 5*time.Second)
	if err != nil {
		return report, err
	}
	defer release()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	definitions, version, err := schema(ctx, tx, s.Dialect())
	if err != nil {
		return report, err
	}
	if version != snapshot.SchemaVersion {
		return report, errors.New("target schema version differs from backup; use the matching binary and migrate an empty database")
	}
	archived := map[string]TableData{}
	for _, table := range snapshot.Tables {
		archived[table.Definition.Name] = table
	}
	for _, definition := range definitions {
		a, _ := json.Marshal(definition)
		b, _ := json.Marshal(archived[definition.Name].Definition)
		if string(a) != string(b) {
			return report, errors.New("target column or foreign-key schema differs from backup")
		}
		if definition.Name == "goose_db_version" {
			continue
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quote(s.Dialect(), definition.Name)).Scan(&count); err != nil {
			return report, err
		}
		if count != 0 {
			return report, errors.New("restore target contains application data; use an empty migrated database")
		}
	}
	ordered, err := insertionOrder(snapshot.Tables)
	if err != nil {
		return report, err
	}
	for _, data := range ordered {
		name := data.Definition.Name
		report.Counts[name] = len(data.Rows)
		if name == "goose_db_version" {
			continue
		}
		columns, placeholders := []string{}, []string{}
		for _, column := range data.Definition.Columns {
			columns = append(columns, quote(s.Dialect(), column.Name))
			placeholders = append(placeholders, "?")
		}
		query := "INSERT INTO " + quote(s.Dialect(), name) + " (" + strings.Join(columns, ",") + ") VALUES(" + strings.Join(placeholders, ",") + ")"
		for _, row := range data.Rows {
			args := make([]any, len(row))
			for i, cell := range row {
				args[i], err = restoreCell(cell, data.Definition.Columns[i], s.Dialect())
				if err != nil {
					return report, err
				}
			}
			if _, err = tx.ExecContext(ctx, query, args...); err != nil {
				return report, fmt.Errorf("cannot restore table %s; no data committed", name)
			}
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quote(s.Dialect(), name)).Scan(&count); err != nil || count != len(data.Rows) {
			return report, errors.New("restored row count does not match backup")
		}
	}
	if dry {
		return report, nil
	}
	if s.Dialect() == database.PostgreSQL {
		for _, definition := range definitions {
			if definition.Name == "goose_db_version" {
				continue
			}
			for _, column := range definition.Columns {
				if !strings.HasPrefix(column.Extra, "identity:") && (column.Default == nil || !strings.HasPrefix(*column.Default, "nextval(")) {
					continue
				}
				var sequence string
				if err = tx.QueryRowContext(ctx, "SELECT pg_get_serial_sequence(?,?)", quote(s.Dialect(), definition.Name), column.Name).Scan(&sequence); err != nil {
					return report, errors.New("cannot identify restored identity sequence")
				}
				table, col := quote(s.Dialect(), definition.Name), quote(s.Dialect(), column.Name)
				query := "SELECT setval(CAST(? AS regclass),COALESCE((SELECT MAX(" + col + ") FROM " + table + "),1),EXISTS(SELECT 1 FROM " + table + "))"
				var value int64
				if err = tx.QueryRowContext(ctx, query, sequence).Scan(&value); err != nil {
					return report, errors.New("cannot reset restored identity sequence")
				}
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return report, errors.New("backup restore commit failed")
	}
	report.Restored = true
	return report, nil
}

func restoreCell(cell Cell, column Column, dialect database.Dialect) (any, error) {
	value, err := decodeCell(cell)
	if err != nil || value == nil {
		return value, err
	}
	// PostgreSQL distinguishes bytea from JSON and text parameters. Preserve
	// byte values for binary columns but bind captured JSON/text as strings.
	if dialect == database.PostgreSQL {
		if raw, ok := value.([]byte); ok && !strings.EqualFold(column.Type, "bytea") {
			return string(raw), nil
		}
	}
	return value, nil
}

func validateCiphertexts(box *cryptobox.Box, data TableData) error {
	columns := map[string]int{}
	for i, column := range data.Definition.Columns {
		columns[column.Name] = i
	}
	for _, row := range data.Rows {
		value := func(name string) string {
			index, ok := columns[name]
			if !ok {
				return ""
			}
			return cellText(row[index])
		}
		checks := map[string]string{}
		switch data.Definition.Name {
		case "users":
			checks["totp_secret"] = "totp:" + value("id")
		case "provider_accounts":
			checks["config_ciphertext"] = "account:" + value("id")
		case "objects":
			checks["data_ciphertext"] = "object:" + value("id")
		case "settings":
			checks["ciphertext"] = "setting:" + value("name")
		case "jobs":
			for field, scope := range map[string]string{"payload_ciphertext": "job-payload:", "checkpoint_ciphertext": "job-checkpoint:", "result_ciphertext": "job-result:", "context_ciphertext": "job-context:"} {
				checks[field] = scope + value("id")
			}
		case "job_items":
			checks["detail_ciphertext"] = "job-item:" + value("job_id") + ":" + value("item_index")
		case "notification_outbox":
			checks["payload_ciphertext"] = "notification:" + value("id")
		case "business_events":
			checks["payload_ciphertext"] = "business-event:" + value("id")
		case "legacy_identities", "legacy_api_credentials":
			checks["api_key_ciphertext"] = "legacy-api:" + value("user_id")
			checks["key_ciphertext"] = "legacy-api:" + value("user_id")
		case "migration_manifests":
			checks["archive_ciphertext"] = "migration-manifest:" + value("id")
		case "migration_archives":
			checks["data_ciphertext"] = "migration-archive:" + value("manifest_id") + ":" + value("source_table") + ":" + value("source_id")
		case "dns_challenge_intents":
			checks["intent_ciphertext"] = "dns-intent:" + value("job_id") + ":" + value("challenge_key")
		}
		for field, scope := range checks {
			ciphertext := value(field)
			if ciphertext == "" {
				continue
			}
			if _, err := box.Open(scope, ciphertext); err != nil {
				return errors.New("database encrypted fields do not match the supplied master key or are damaged")
			}
		}
	}
	return nil
}
