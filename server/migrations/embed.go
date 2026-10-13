package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

// Files contains the versioned schemas shipped with the binary.
//
//go:embed *.sql postgresql/*.sql sqlite/*.sql
var Files embed.FS

// FilesFor selects a database's versioned schema without changing MySQL history.
func FilesFor(driver string) (fs.FS, error) {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "mysql":
		return Files, nil
	case "postgres", "postgresql", "pgx":
		return fs.Sub(Files, "postgresql")
	case "sqlite", "sqlite3":
		return fs.Sub(Files, "sqlite")
	default:
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
}
