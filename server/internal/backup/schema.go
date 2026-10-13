package backup

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"

	"github.com/dns-manager/dnsmgr/server/internal/database"
)

func quote(dialect database.Dialect, name string) string {
	if dialect == database.MySQL {
		return "`" + name + "`"
	}
	return `"` + name + `"`
}

func schema(ctx context.Context, q queryer, dialects ...database.Dialect) ([]Definition, int64, error) {
	dialect := database.MySQL
	if len(dialects) > 0 {
		dialect = dialects[0]
	}
	if dialect == database.MySQL {
		return mysqlSchema(ctx, q)
	}
	query := "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE' ORDER BY table_name"
	if dialect == database.SQLite {
		query = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name"
	}
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, 0, errors.New("cannot inspect database schema")
	}
	allowed := map[string]bool{}
	for _, name := range Tables {
		allowed[name] = true
	}
	names := []string{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if !allowed[name] || !safeName.MatchString(name) {
			rows.Close()
			return nil, 0, errors.New("database contains an unknown table")
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
		var definition Definition
		if dialect == database.SQLite {
			definition, err = sqliteDefinition(ctx, q, name)
		} else {
			definition, err = postgresDefinition(ctx, q, name)
		}
		if err != nil {
			return nil, 0, err
		}
		definitions = append(definitions, definition)
	}
	var version int64
	if err = q.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_id),0) FROM goose_db_version WHERE is_applied=TRUE").Scan(&version); err != nil {
		return nil, 0, err
	}
	return definitions, version, nil
}

func postgresDefinition(ctx context.Context, q queryer, name string) (Definition, error) {
	d := Definition{Name: name, Columns: []Column{}, PrimaryKey: []string{}, ForeignKeys: []ForeignKey{}}
	const columnsQuery = `SELECT a.attname, pg_catalog.format_type(a.atttypid,a.atttypmod),
		a.attnotnull, pg_catalog.pg_get_expr(ad.adbin,ad.adrelid), a.attidentity, a.attgenerated
		FROM pg_catalog.pg_attribute a
		JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
		JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
		LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
		WHERE n.nspname=current_schema() AND c.relname=? AND a.attnum>0 AND NOT a.attisdropped
		ORDER BY a.attnum`
	rows, err := q.QueryContext(ctx, columnsQuery, name)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var c Column
		var notNull bool
		var value sql.NullString
		var identity, generated string
		if err = rows.Scan(&c.Name, &c.Type, &notNull, &value, &identity, &generated); err != nil {
			rows.Close()
			return d, err
		}
		if !safeName.MatchString(c.Name) || generated != "" {
			rows.Close()
			return d, errors.New("database contains an unsafe or generated schema column")
		}
		c.Nullable = !notNull
		if value.Valid {
			v := value.String
			c.Default = &v
		}
		if identity != "" {
			c.Extra = "identity:" + identity
		}
		d.Columns = append(d.Columns, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	const constraintQuery = `SELECT con.contype, a.attname, COALESCE(rc.relname,''), COALESCE(ra.attname,''), con.confupdtype, con.confdeltype, con.confmatchtype, COALESCE(rn.nspname=current_schema(),FALSE)
		FROM pg_catalog.pg_constraint con
		JOIN pg_catalog.pg_class c ON c.oid=con.conrelid
		JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
		JOIN LATERAL unnest(con.conkey) WITH ORDINALITY k(attnum,ord) ON TRUE
		JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.attnum
		LEFT JOIN pg_catalog.pg_class rc ON rc.oid=con.confrelid
		LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid=rc.relnamespace
		LEFT JOIN pg_catalog.pg_attribute ra ON ra.attrelid=con.confrelid AND ra.attnum=con.confkey[k.ord::int]
		WHERE n.nspname=current_schema() AND c.relname=? AND con.contype IN ('p','f')
		ORDER BY con.conname,k.ord`
	rows, err = q.QueryContext(ctx, constraintQuery, name)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var kind, column, table, referenced, update, deleteAction, match string
		var local bool
		if err = rows.Scan(&kind, &column, &table, &referenced, &update, &deleteAction, &match, &local); err != nil {
			rows.Close()
			return d, err
		}
		if kind == "p" {
			d.PrimaryKey = append(d.PrimaryKey, column)
		} else {
			if !local {
				rows.Close()
				return d, errors.New("database contains a foreign key outside the application schema")
			}
			d.ForeignKeys = append(d.ForeignKeys, ForeignKey{Column: column, Table: table, ReferencedColumn: referenced, OnUpdate: update, OnDelete: deleteAction, Match: match})
		}
	}
	err = rows.Err()
	rows.Close()
	return d, err
}

func sqliteDefinition(ctx context.Context, q queryer, name string) (Definition, error) {
	d := Definition{Name: name, Columns: []Column{}, PrimaryKey: []string{}, ForeignKeys: []ForeignKey{}}
	rows, err := q.QueryContext(ctx, "PRAGMA table_xinfo("+quote(database.SQLite, name)+")")
	if err != nil {
		return d, err
	}
	primary := map[int]string{}
	for rows.Next() {
		var c Column
		var index, notNull, pk, hidden int
		var value sql.NullString
		if err = rows.Scan(&index, &c.Name, &c.Type, &notNull, &value, &pk, &hidden); err != nil {
			rows.Close()
			return d, err
		}
		if !safeName.MatchString(c.Name) || hidden != 0 {
			rows.Close()
			return d, errors.New("database contains an unsafe or generated schema column")
		}
		c.Nullable = notNull == 0
		if value.Valid {
			v := value.String
			c.Default = &v
		}
		if pk > 0 {
			primary[pk] = c.Name
			if strings.EqualFold(c.Type, "INTEGER") {
				c.Nullable = false
			}
		}
		d.Columns = append(d.Columns, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	positions := []int{}
	for position := range primary {
		positions = append(positions, position)
	}
	sort.Ints(positions)
	for _, position := range positions {
		d.PrimaryKey = append(d.PrimaryKey, primary[position])
	}
	var ddl string
	if err = q.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&ddl); err != nil {
		return d, err
	}
	if strings.Contains(strings.ToUpper(ddl), "AUTOINCREMENT") && len(d.PrimaryKey) == 1 {
		for i := range d.Columns {
			if d.Columns[i].Name == d.PrimaryKey[0] {
				d.Columns[i].Extra = "auto_increment"
			}
		}
	}
	rows, err = q.QueryContext(ctx, "PRAGMA foreign_key_list("+quote(database.SQLite, name)+")")
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var fk ForeignKey
		var id, sequence int
		var update, deleteAction, match string
		if err = rows.Scan(&id, &sequence, &fk.Table, &fk.Column, &fk.ReferencedColumn, &update, &deleteAction, &match); err != nil {
			rows.Close()
			return d, err
		}
		fk.OnUpdate, fk.OnDelete, fk.Match = update, deleteAction, match
		d.ForeignKeys = append(d.ForeignKeys, fk)
	}
	err = rows.Err()
	rows.Close()
	return d, err
}
