package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"path"
	"strconv"
	"strings"
)

type fnosProvider struct{ *sshProvider }

func (p *fnosProvider) read(ctx context.Context, client *ssh.Client, command string) ([]byte, error) {
	session, e := client.NewSession()
	if e != nil {
		return nil, e
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdout = &limitedOutput{buffer: &out, limit: 16 << 20}
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	if e = session.Run(command); e != nil {
		return nil, fmt.Errorf("fnOS SSH command failed: %w", e)
	}
	if out.Len() > 16<<20 {
		return nil, errors.New("fnOS response exceeds limit")
	}
	return out.Bytes(), nil
}
func shQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func (p *fnosProvider) write(ctx context.Context, client *ssh.Client, destination string, data []byte) error {
	if e := remotePath(destination, p.opts.RemoteAllowedDirectories); e != nil {
		return e
	}
	session, e := client.NewSession()
	if e != nil {
		return e
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(data)
	command, err := fnosWriteCommand(destination, p.opts.RemoteAllowedDirectories)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	if e = session.Run(command); e != nil {
		return errors.New("fnOS certificate write failed; configure passwordless sudo for deployment")
	}
	return nil
}

type limitedOutput struct {
	buffer *bytes.Buffer
	limit  int
}

func (w *limitedOutput) Write(raw []byte) (int, error) {
	if len(raw) > w.limit-w.buffer.Len() {
		return 0, errors.New("remote command response exceeds limit")
	}
	return w.buffer.Write(raw)
}
func fnosWriteCommand(destination string, allowed []string) (string, error) {
	if err := remotePath(destination, allowed); err != nil {
		return "", err
	}
	patterns := []string{}
	for _, base := range allowed {
		if !path.IsAbs(base) || path.Clean(base) != base || strings.ContainsRune(base, 0) {
			continue
		}
		patterns = append(patterns, shQuote(base), shQuote(strings.TrimRight(base, "/"))+"/*")
	}
	if len(patterns) == 0 {
		return "", errors.New("canonical remote allowed directories required")
	}
	name := path.Base(destination)
	temp := ".dnsmgr-" + randomSuffix()
	// cd pins the working directory before its physical path is checked; writes stay relative.
	script := "set -eu; cd -- " + shQuote(path.Dir(destination)) + "; actual=$(pwd -P); case \"$actual\" in " + strings.Join(patterns, "|") + ") ;; *) exit 1 ;; esac; [ ! -L " + shQuote(name) + " ] || exit 1; umask 077; set -C; trap " + shQuote("rm -f -- "+shQuote(temp)) + " EXIT; cat > " + shQuote(temp) + "; chmod 600 " + shQuote(temp) + "; mv -f -- " + shQuote(temp) + " " + shQuote(name)
	return "sudo -n sh -c " + shQuote(script), nil
}

func (p *fnosProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, e := parsePair(chain, key)
	if e != nil {
		return info, e
	}
	if len(target.Domains) == 0 {
		return info, errors.New("fnOS deployment domains are required")
	}
	client, e := p.connect(ctx)
	if e != nil {
		return info, e
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	raw, e := p.read(ctx, client, "cat /usr/trim/etc/network_cert_all.conf")
	if e != nil {
		return info, e
	}
	var rows []map[string]any
	if json.Unmarshal(raw, &rows) != nil {
		return info, errors.New("invalid fnOS certificate inventory")
	}
	matched := map[string]map[string]any{}
	ids := []string{}
	for _, row := range rows {
		if matchesDomains(stringList(row["san"]), target.Domains) {
			id := text(row["privateKey"])
			cert := text(row["certificate"])
			if id == "" || cert == "" || !path.IsAbs(cert) || !path.IsAbs(id) {
				return info, errors.New("fnOS certificate paths unavailable")
			}
			ids = append(ids, id)
			matched[id] = row
		}
	}
	info, e = batch(ctx, ids, info, func(id string) error {
		row := matched[id]
		certificate := text(row["certificate"])
		if e := remotePath(certificate, p.opts.RemoteAllowedDirectories); e != nil {
			return e
		}
		if e := remotePath(id, p.opts.RemoteAllowedDirectories); e != nil {
			return e
		}
		if e := p.write(ctx, client, certificate, []byte(chain)); e != nil {
			return e
		}
		if e := p.write(ctx, client, id, []byte(key)); e != nil {
			return e
		}
		quoteSQL := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }
		sql := "UPDATE cert SET valid_to=" + strconv.FormatInt(leaf.NotAfter.UnixMilli(), 10) + ",valid_from=" + strconv.FormatInt(leaf.NotBefore.UnixMilli(), 10) + ",issued_by=" + quoteSQL(leaf.Issuer.CommonName) + ",updated_time=" + strconv.FormatInt(p.opts.Now().UnixMilli(), 10) + " WHERE private_key=" + quoteSQL(id)
		_, e := p.read(ctx, client, "sudo -n -u postgres psql -v ON_ERROR_STOP=1 -d trim_connect -c "+shQuote(sql))
		return e
	})
	if e != nil {
		return info, e
	}
	for _, service := range []string{"webdav.service", "smbftpd.service", "trim_nginx.service"} {
		if _, e = p.read(ctx, client, "sudo -n systemctl restart "+service); e != nil {
			return info, e
		}
	}
	return info, nil
}
