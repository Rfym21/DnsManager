package deploy

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type sshProvider struct {
	cfg  map[string]string
	opts Options
}

func (p *sshProvider) connect(ctx context.Context) (*ssh.Client, error) {
	host := p.cfg["host"]
	port := p.cfg["port"]
	if port == "" {
		port = "22"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || host == "" || p.cfg["username"] == "" {
		return nil, errors.New("SSH host, valid port and username are required")
	}
	var auth ssh.AuthMethod
	if p.cfg["auth"] == "1" {
		var signer ssh.Signer
		if p.cfg["passphrase"] != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(p.cfg["privatekey"]), []byte(p.cfg["passphrase"]))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(p.cfg["privatekey"]))
		}
		if err != nil {
			return nil, errors.New("invalid SSH private key or passphrase")
		}
		auth = ssh.PublicKeys(signer)
	} else {
		if p.cfg["password"] == "" {
			return nil, errors.New("SSH password is required")
		}
		auth = ssh.Password(p.cfg["password"])
	}
	var callback ssh.HostKeyCallback
	if p.cfg["host_key"] != "" {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.cfg["host_key"]))
		if err != nil {
			return nil, errors.New("invalid pinned SSH host key")
		}
		callback = ssh.FixedHostKey(key)
	} else if p.cfg["known_hosts_file"] != "" {
		callback, err = knownhosts.New(p.cfg["known_hosts_file"])
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("pinned SSH host key or known_hosts_file is required")
	}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	address := net.JoinHostPort(host, port)
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	connection, channels, requests, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{User: p.cfg["username"], Auth: []ssh.AuthMethod{auth}, HostKeyCallback: callback, Timeout: 15 * time.Second})
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(connection, channels, requests), nil
}
func (p *sshProvider) Validate(ctx context.Context) error {
	client, err := p.connect(ctx)
	if err != nil {
		return err
	}
	return client.Close()
}
func (p *sshProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
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
	client, err := p.connect(ctx)
	if err != nil {
		return info, err
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	if err = p.hooks(ctx, client, target.Config["cmd_pre"]); err != nil {
		return info, err
	}
	fs, err := sftp.NewClient(client)
	if err != nil {
		return info, err
	}
	defer fs.Close()
	written := []string{}
	for _, file := range files {
		parent, err := fs.RealPath(path.Dir(file.path))
		if err != nil {
			return info, err
		}
		destination := path.Join(parent, path.Base(file.path))
		if err = remotePath(destination, p.opts.RemoteAllowedDirectories); err != nil {
			return info, err
		}
		if stat, e := fs.Lstat(destination); e == nil && stat.Mode()&os.ModeSymlink != 0 {
			return info, errors.New("remote symbolic link destination is prohibited")
		}
		temp := destination + ".dnsmgr-" + randomSuffix()
		f, err := fs.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return info, err
		}
		err = f.Chmod(file.mode)
		if err == nil {
			_, err = f.Write(file.data)
		}
		if err == nil {
			if _, supported := fs.HasExtension("fsync@openssh.com"); supported {
				err = f.Sync()
			}
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = fs.PosixRename(temp, destination)
		}
		if err != nil {
			_ = fs.Remove(temp)
			info["written_paths"] = written
			return info, err
		}
		written = append(written, destination)
	}
	info["written_paths"] = written
	info["fingerprint"] = sha256hex(leaf.Raw)
	if target.Config["format"] == "pfx" && target.Config["uptype"] == "1" {
		if p.cfg["windows"] != "1" {
			return info, errors.New("IIS deployment requires a Windows SSH account")
		}
		domain := target.Config["iis_domain"]
		if !strings.Contains(domain, ":") {
			domain += ":443"
		}
		if strings.ContainsAny(domain, "\r\n'\";$` ") {
			return info, errors.New("invalid IIS hostname binding")
		}
		hash := sha1.Sum(leaf.Raw)
		thumbprint := strings.ToUpper(hex.EncodeToString(hash[:]))
		script := "$secure = ConvertTo-SecureString '" + psQuote(target.Config["pfx_pass"]) + "' -AsPlainText -Force; Import-PfxCertificate -FilePath '" + psQuote(strings.TrimPrefix(target.Config["pfx_file"], "/")) + "' -CertStoreLocation Cert:\\LocalMachine\\My -Password $secure | Out-Null; netsh http delete sslcert hostnameport='" + domain + "'; netsh http add sslcert hostnameport='" + domain + "' certhash=" + thumbprint + " certstorename=MY appid='{8bbcae3d-7a76-41a4-a6bb-93f192344665}'"
		if err = p.run(ctx, client, "powershell -NoProfile -NonInteractive -Command \""+strings.ReplaceAll(script, "\"", "`\"")+"\""); err != nil {
			return info, err
		}
	} else {
		err = p.hooks(ctx, client, target.Config["cmd"])
	}
	return info, err
}
func remotePath(destination string, allowed []string) error {
	if !strings.HasPrefix(destination, "/") || strings.ContainsRune(destination, 0) || path.Clean(destination) != destination {
		return errors.New("remote destination must be canonical and absolute")
	}
	if len(allowed) == 0 {
		return errors.New("administrator must configure allowed remote deployment directories")
	}
	for _, root := range allowed {
		root = path.Clean(root)
		if destination == root || strings.HasPrefix(destination, root+"/") {
			return nil
		}
	}
	return errors.New("remote destination is outside administrator allowed directories")
}
func (p *sshProvider) hooks(ctx context.Context, client *ssh.Client, script string) error {
	if strings.TrimSpace(script) == "" {
		return nil
	}
	if !p.opts.AllowTrustedHooks {
		return errors.New("administrator must enable trusted deployment hooks")
	}
	for _, line := range splitLines(script) {
		if err := p.run(ctx, client, line); err != nil {
			return err
		}
	}
	return nil
}
func (p *sshProvider) run(ctx context.Context, client *ssh.Client, command string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	timeout := p.opts.HookTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	hookCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(hookCtx, func() { session.Close() })
	defer stop()
	if err = session.Run(command); err != nil {
		return fmt.Errorf("SSH deployment command failed: %w", err)
	}
	return nil
}
func psQuote(value string) string { return strings.ReplaceAll(value, "'", "''") }
