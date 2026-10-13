package config

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen, DSN, StateDir, MasterKeyFile, PublicURL, SetupToken string
	SecureCookies                                               bool
	SessionTTL                                                  time.Duration
	WorkerConcurrency                                           int
}

func Load() (Config, error) {
	c := Config{
		Listen:            get("LISTEN_ADDR", "127.0.0.1:8080"),
		StateDir:          get("STATE_DIR", ".state"),
		PublicURL:         get("PUBLIC_URL", "http://127.0.0.1:8080"),
		SecureCookies:     strings.HasPrefix(get("PUBLIC_URL", "http://127.0.0.1:8080"), "https://"),
		SessionTTL:        12 * time.Hour,
		WorkerConcurrency: 4,
	}
	var err error
	c.DSN, err = secret("DATABASE_DSN")
	if err != nil {
		return c, err
	}
	if c.DSN == "" {
		return c, errors.New("DATABASE_DSN or DATABASE_DSN_FILE is required")
	}
	c.SetupToken, err = secret("SETUP_TOKEN")
	if err != nil {
		return c, err
	}
	c.MasterKeyFile = get("MASTER_KEY_FILE", filepath.Join(c.StateDir, "master.key"))
	public, err := url.Parse(c.PublicURL)
	if err != nil || public.Host == "" || public.User != nil || (public.Scheme != "http" && public.Scheme != "https") || public.RawQuery != "" || public.Fragment != "" || (public.Path != "" && public.Path != "/") {
		return c, errors.New("PUBLIC_URL must be an http(s) origin without credentials or a path")
	}
	if raw := os.Getenv("WORKER_CONCURRENCY"); raw != "" {
		c.WorkerConcurrency, err = strconv.Atoi(raw)
		if err != nil || c.WorkerConcurrency < 1 || c.WorkerConcurrency > 32 {
			return c, errors.New("WORKER_CONCURRENCY must be between 1 and 32")
		}
	}
	return c, nil
}

func secret(name string) (string, error) {
	if filename := os.Getenv(name + "_FILE"); filename != "" {
		b, err := os.ReadFile(filename)
		if err != nil {
			return "", errors.New("cannot read " + name + "_FILE")
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(name), nil
}

func get(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
