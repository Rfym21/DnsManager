package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/automation"
	"github.com/dns-manager/dnsmgr/server/internal/config"
	"github.com/dns-manager/dnsmgr/server/internal/cryptobox"
	"github.com/dns-manager/dnsmgr/server/internal/httpapi"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

// version is set by release builds using -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("command failed", "message", err.Error())
		os.Exit(1)
	}
}
func run() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	flags := flag.NewFlagSet("dnsmgr", flag.ContinueOnError)
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	command := "serve"
	if flags.NArg() > 0 {
		command = flags.Arg(0)
	}
	if command == "version" {
		fmt.Printf("dnsmgr %s\n", version)
		return nil
	}
	switch command {
	case "serve", "worker", "migrate", "backup", "restore", "recover":
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if command == "restore" {
		if _, err = os.Stat(cfg.MasterKeyFile); err != nil {
			return errors.New("restore requires the existing MASTER_KEY_FILE")
		}
	}
	box, err := cryptobox.LoadOrCreate(cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := store.Open(ctx, cfg.DSN, box)
	if err != nil {
		return err
	}
	defer s.Close()
	if command == "backup" || command == "restore" {
		return backupCommand(ctx, s, box, flags.Args())
	}
	if command == "recover" {
		return recoverUser(ctx, s, flags.Args()[1:])
	}
	if command == "migrate" {
		if err = s.Migrate(ctx); err != nil {
			return err
		}
		slog.Info("schema migrations completed")
		return nil
	}
	if command == "worker" {
		runner := &automation.Runner{Store: s}
		handlers := runner.Handlers()
		for kind, handler := range runner.CertificateHandlers() {
			handlers[kind] = handler
		}
		for kind, handler := range runner.NotificationHandlers() {
			handlers[kind] = handler
		}
		worker := &automation.Worker{Store: s, Concurrency: cfg.WorkerConcurrency, Handlers: handlers, Schedule: runner.Tick}
		slog.Info("worker started", "concurrency", cfg.WorkerConcurrency)
		return worker.Run(ctx)
	}
	api := httpapi.New(s, cfg)
	server := &http.Server{Addr: cfg.Listen, Handler: api.Router, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	errorsCh := make(chan error, 1)
	go func() { slog.Info("API listening", "address", cfg.Listen); errorsCh <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-errorsCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
