package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionCommandDoesNotLoadConfiguration(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "private-state", "master.key")
	t.Setenv("DATABASE_DSN_FILE", filepath.Join(dir, "missing-dsn"))
	t.Setenv("MASTER_KEY_FILE", keyPath)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	args, stdout, previousVersion, logger := os.Args, os.Stdout, version, slog.Default()
	t.Cleanup(func() {
		os.Args, os.Stdout, version = args, stdout, previousVersion
		slog.SetDefault(logger)
		reader.Close()
		writer.Close()
	})
	os.Args, os.Stdout, version = []string{"dnsmgr", "version"}, writer, "2.21-test"
	if err := run(); err != nil {
		t.Fatalf("version command reached configuration: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "dnsmgr 2.21-test\n" {
		t.Fatalf("version output = %q", output)
	}
	if _, err := os.Stat(filepath.Dir(keyPath)); !os.IsNotExist(err) {
		t.Fatalf("version command touched state directory: %v", err)
	}
}

func TestRemovedMigrationCommandDoesNotLoadConfiguration(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "private-state", "master.key")
	t.Setenv("DATABASE_DSN_FILE", filepath.Join(dir, "missing-dsn"))
	t.Setenv("MASTER_KEY_FILE", keyPath)
	args := os.Args
	t.Cleanup(func() { os.Args = args })
	os.Args = []string{"dnsmgr", "migration", "export"}
	if err := run(); err == nil || err.Error() != `unknown command "migration"` {
		t.Fatalf("removed command reached configuration: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(keyPath)); !os.IsNotExist(err) {
		t.Fatalf("removed command touched state directory: %v", err)
	}
}
