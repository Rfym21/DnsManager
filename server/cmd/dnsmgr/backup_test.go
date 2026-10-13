package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dns-manager/dnsmgr/server/internal/backup"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func TestBackupRestoreCLI(t *testing.T) {
	sourcePath, targetPath := os.Getenv("BACKUP_CLI_SOURCE_DSN_FILE"), os.Getenv("BACKUP_CLI_TARGET_DSN_FILE")
	if sourcePath == "" || targetPath == "" {
		t.Skip("dedicated backup CLI source and restore databases required")
	}
	ctx := context.Background()
	box, _ := cryptobox.New(make([]byte, 32))
	open := func(path string) *store.Store {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		s, e := store.Open(ctx, strings.TrimSpace(string(raw)), box)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { s.Close() })
		if e = s.Migrate(ctx); e != nil {
			t.Fatal(e)
		}
		return s
	}
	source, target := open(sourcePath), open(targetPath)
	t.Cleanup(func() {
		source.DB.Exec("DELETE FROM settings WHERE name='backup-cli-fixture'")
		target.DB.Exec("DELETE FROM settings WHERE name='backup-cli-fixture'")
	})
	if e := source.SaveSetting(ctx, "backup-cli-fixture", map[string]string{"value": "fixture-private-value"}); e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(t.TempDir(), "full-backup.enc")
	if e := backupCommand(ctx, source, box, []string{"backup", "--archive", archive}); e == nil {
		t.Fatal("backup CLI without freeze accepted")
	}
	if e := backupCommand(ctx, source, box, []string{"backup", "--archive", archive, "--go-frozen"}); e != nil {
		t.Fatal(e)
	}
	if e := backupCommand(ctx, target, box, []string{"restore", "--archive", archive, "--go-frozen", "--dry-run"}); e != nil {
		t.Fatal(e)
	}
	if e := backupCommand(ctx, target, box, []string{"restore", "--archive", archive, "--go-frozen"}); e != nil {
		t.Fatal(e)
	}
	var value map[string]string
	if e := target.Setting(ctx, "backup-cli-fixture", &value); e != nil || value["value"] != "fixture-private-value" {
		t.Fatal("restored value", e)
	}
	snapshot, e := backup.Read(archive, box)
	if e != nil || len(snapshot.Tables) != len(backup.Tables) {
		t.Fatal("CLI archive missing tables", e)
	}
}
