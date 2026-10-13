package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type localProvider struct{ opts Options }

func (p *localProvider) Validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(p.opts.AllowedDirectories) == 0 {
		return errors.New("administrator must configure allowed local deployment directories")
	}
	for _, dir := range p.opts.AllowedDirectories {
		if !filepath.IsAbs(dir) {
			return errors.New("allowed directory must be absolute")
		}
		if stat, err := os.Stat(dir); err != nil || !stat.IsDir() {
			return errors.New("allowed deployment directory is unavailable")
		}
	}
	return nil
}
func (p *localProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	if err := p.Validate(ctx); err != nil {
		return info, err
	}
	leaf, _, _, err := parsePair(chain, key)
	if err != nil {
		return info, err
	}
	files, err := deploymentFiles(chain, key, target.Config)
	if err != nil {
		return info, err
	}
	for i := range files {
		files[i].path, err = canonicalDestination(files[i].path, p.opts.AllowedDirectories)
		if err != nil {
			return info, err
		}
	}
	if err = runLocalHooks(ctx, p.opts, target.Config["cmd_pre"]); err != nil {
		return info, err
	}
	written := []string{}
	for _, file := range files {
		if err = ctx.Err(); err != nil {
			return info, err
		}
		if err = atomicWrite(file.path, file.data, file.mode, p.opts.AllowedDirectories); err != nil {
			info["written_paths"] = written
			return info, fmt.Errorf("certificate file update failed after %d writes: %w", len(written), err)
		}
		written = append(written, file.path)
	}
	info["written_paths"] = written
	info["fingerprint"] = sha256hex(leaf.Raw)
	if err = runLocalHooks(ctx, p.opts, target.Config["cmd"]); err != nil {
		return info, err
	}
	return info, nil
}

type deploymentFile struct {
	path string
	data []byte
	mode os.FileMode
}

func deploymentFiles(chain, key string, cfg map[string]string) ([]deploymentFile, error) {
	switch cfg["format"] {
	case "", "pem":
		if cfg["pem_cert_file"] == "" || cfg["pem_key_file"] == "" {
			return nil, errors.New("certificate and private key paths are required")
		}
		if cfg["pem_cert_file"] == cfg["pem_key_file"] {
			return nil, errors.New("certificate and private key paths must differ")
		}
		return []deploymentFile{{cfg["pem_cert_file"], []byte(chain), 0644}, {cfg["pem_key_file"], []byte(key), 0600}}, nil
	case "pfx":
		if cfg["pfx_file"] == "" {
			return nil, errors.New("PFX destination is required")
		}
		data, err := encodePFX(chain, key, cfg["pfx_pass"])
		return []deploymentFile{{cfg["pfx_file"], data, 0600}}, err
	default:
		return nil, errors.New("certificate format must be pem or pfx")
	}
}
func canonicalDestination(path string, allowed []string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", errors.New("destination must be an absolute path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", errors.New("destination parent directory must exist")
	}
	destination := filepath.Join(parent, filepath.Base(path))
	if stat, err := os.Lstat(destination); err == nil && stat.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("symbolic link destinations are prohibited")
	}
	for _, base := range allowed {
		root, err := filepath.EvalSymlinks(base)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, destination)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return destination, nil
		}
	}
	return "", errors.New("destination is outside administrator allowed directories")
}

// OpenRoot confines every filesystem operation even if a parent is replaced by a symlink.
func atomicWrite(path string, data []byte, mode os.FileMode, allowed []string) error {
	for _, base := range allowed {
		canonical, err := filepath.EvalSymlinks(base)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(canonical, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		root, err := os.OpenRoot(canonical)
		if err != nil {
			return err
		}
		defer root.Close()
		parent, err := root.OpenRoot(filepath.Dir(rel))
		if err != nil {
			return err
		}
		defer parent.Close()
		name := filepath.Base(rel)
		if stat, err := parent.Lstat(name); err == nil && stat.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic link destinations are prohibited")
		}
		temp := ".dnsmgr-" + randomSuffix()
		file, err := parent.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		defer parent.Remove(temp)
		if err = file.Chmod(mode); err == nil {
			_, err = file.Write(data)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = parent.Rename(temp, name); err != nil {
			return err
		}
		dir, err := parent.Open(".")
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	return errors.New("destination is outside administrator allowed directories")
}
func runLocalHooks(ctx context.Context, opts Options, script string) error {
	if strings.TrimSpace(script) == "" {
		return nil
	}
	if !opts.AllowTrustedHooks {
		return errors.New("administrator must enable trusted deployment hooks")
	}
	timeout := opts.HookTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	for _, line := range splitLines(script) {
		hookCtx, cancel := context.WithTimeout(ctx, timeout)
		command := exec.CommandContext(hookCtx, "/bin/sh", "-c", line)
		command.Env = os.Environ()
		err := command.Run()
		cancel()
		if err != nil {
			return fmt.Errorf("trusted deployment hook failed: %w", err)
		}
	}
	return nil
}
func randomSuffix() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
