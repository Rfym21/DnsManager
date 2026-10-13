package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/jlaffaye/ftp"
)

type ftpProvider struct {
	cfg  map[string]string
	opts Options
}

func (p *ftpProvider) connect(ctx context.Context) (*ftp.ServerConn, error) {
	port := p.cfg["port"]
	if port == "" {
		port = "21"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || p.cfg["host"] == "" || p.cfg["username"] == "" || p.cfg["password"] == "" {
		return nil, errors.New("FTP host, valid port, username and password are required")
	}
	options := []ftp.DialOption{ftp.DialWithContext(ctx), ftp.DialWithTimeout(20 * time.Second)}
	if p.cfg["secure"] == "1" {
		options = append(options, ftp.DialWithExplicitTLS(&tls.Config{ServerName: p.cfg["host"], MinVersion: tls.VersionTLS12}))
	}
	connection, err := ftp.Dial(net.JoinHostPort(p.cfg["host"], port), options...)
	if err != nil {
		return nil, err
	}
	if err = connection.Login(p.cfg["username"], p.cfg["password"]); err != nil {
		_ = connection.Quit()
		return nil, err
	}
	return connection, nil
}
func (p *ftpProvider) Validate(ctx context.Context) error {
	connection, err := p.connect(ctx)
	if err != nil {
		return err
	}
	return connection.Quit()
}
func (p *ftpProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	leaf, _, _, err := parsePair(chain, key)
	if err != nil {
		return info, err
	}
	files, err := deploymentFiles(chain, key, target.Config)
	if err != nil {
		return info, err
	}
	for _, file := range files {
		if err = remotePath(file.path, p.opts.RemoteAllowedDirectories); err != nil {
			return info, err
		}
	}
	connection, err := p.connect(ctx)
	if err != nil {
		return info, err
	}
	defer connection.Quit()
	written := []string{}
	for _, file := range files {
		if err = ctx.Err(); err != nil {
			return info, err
		}
		temp := file.path + ".dnsmgr-" + randomSuffix()
		if err = connection.Stor(temp, bytes.NewReader(file.data)); err != nil {
			return info, err
		}
		if err = connection.Rename(temp, file.path); err != nil {
			_ = connection.Delete(temp)
			info["written_paths"] = written
			return info, err
		}
		written = append(written, file.path)
	}
	info["written_paths"] = written
	info["fingerprint"] = sha256hex(leaf.Raw)
	return info, nil
}
