package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"

	"github.com/dns-manager/dnsmgr/server/internal/backup"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

// args starts with backup or restore, followed by archive/freeze options.
func backupCommand(ctx context.Context, s *store.Store, box *cryptobox.Box, args []string) error {
	if len(args) == 0 || args[0] != "backup" && args[0] != "restore" {
		return errors.New("usage: backup|restore --archive PATH --go-frozen [--dry-run]")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := flags.String("archive", "", "encrypted backup archive path")
	frozen := flags.Bool("go-frozen", false, "Go API writes and workers have been stopped")
	dry := flags.Bool("dry-run", false, "restore all rows in a transaction and roll back")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("--archive is required")
	}
	var report backup.Report
	var err error
	if args[0] == "backup" {
		if *dry {
			return errors.New("--dry-run is available for restore")
		}
		var snapshot backup.Snapshot
		snapshot, report, err = backup.Capture(ctx, s, *frozen)
		if err == nil {
			err = backup.Write(*path, box, snapshot)
		}
	} else {
		var snapshot backup.Snapshot
		snapshot, err = backup.Read(*path, box)
		if err == nil {
			report, err = backup.Restore(ctx, s, snapshot, *frozen, *dry)
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}
