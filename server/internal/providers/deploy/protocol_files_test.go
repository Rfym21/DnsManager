package deploy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sshWireFixture struct {
	listener net.Listener
	signer   ssh.Signer
	mu       sync.Mutex
	commands []string
	bodies   [][]byte
	failHook bool
}

func newSSHWireFixture(t *testing.T, failHook bool) *sshWireFixture {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &sshWireFixture{listener: listener, signer: signer, failHook: failHook}
	config := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if metadata.User() != "fixture-user" || string(password) != "fixture-secret" {
			return nil, errors.New("fixture auth rejected")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	go func() {
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer socket.Close()
				connection, channels, requests, err := ssh.NewServerConn(socket, config)
				if err != nil {
					return
				}
				defer connection.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						incoming.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, reqs, err := incoming.Accept()
					if err != nil {
						return
					}
					go f.session(t, channel, reqs)
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return f
}
func (f *sshWireFixture) session(t *testing.T, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for request := range requests {
		switch request.Type {
		case "subsystem":
			var subsystem struct{ Name string }
			ssh.Unmarshal(request.Payload, &subsystem)
			if subsystem.Name != "sftp" {
				request.Reply(false, nil)
				continue
			}
			request.Reply(true, nil)
			server, err := sftp.NewServer(channel)
			if err != nil {
				t.Error(err)
				return
			}
			defer server.Close()
			if err = server.Serve(); err != nil && !errors.Is(err, io.EOF) {
				t.Error(err)
			}
			return
		case "exec":
			var payload struct{ Command string }
			ssh.Unmarshal(request.Payload, &payload)
			request.Reply(true, nil)
			f.mu.Lock()
			f.commands = append(f.commands, payload.Command)
			f.mu.Unlock()
			status := uint32(0)
			if payload.Command == "fixture-reload" {
				if f.failHook {
					status = 1
				}
			} else if payload.Command == "cat /usr/trim/etc/network_cert_all.conf" {
				io.WriteString(channel, `[{"san":["example.com"],"certificate":"/fixture/cert.pem","privateKey":"/fixture/key.pem"}]`)
			} else if strings.HasPrefix(payload.Command, "sudo -n sh -c ") {
				body, err := io.ReadAll(channel)
				if err != nil {
					t.Error(err)
				}
				f.mu.Lock()
				f.bodies = append(f.bodies, body)
				count := len(f.bodies)
				f.mu.Unlock()
				if f.failHook && count == 1 {
					status = 1
				}
			} else if strings.HasPrefix(payload.Command, "sudo -n -u postgres psql ") || strings.HasPrefix(payload.Command, "sudo -n systemctl restart ") {
			} else {
				t.Errorf("unexpected SSH command %s", payload.Command)
				status = 1
			}
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			return
		default:
			request.Reply(false, nil)
		}
	}
}
func (f *sshWireFixture) config() map[string]string {
	host, port, _ := net.SplitHostPort(f.listener.Addr().String())
	return map[string]string{"host": host, "port": port, "username": "fixture-user", "password": "fixture-secret", "host_key": string(ssh.MarshalAuthorizedKey(f.signer.PublicKey()))}
}

func TestSSHDeploymentWireWritesPermissionsAndReloadOutcome(t *testing.T) {
	chain, key := deployFixture(t)
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("reload_failed_%t", failed), func(t *testing.T) {
			remote := newSSHWireFixture(t, failed)
			root := t.TempDir()
			provider, err := New("ssh", remote.config(), Options{RemoteAllowedDirectories: []string{root}, AllowTrustedHooks: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			info, err := provider.Deploy(ctx, chain, key, Target{Config: map[string]string{"format": "pem", "pem_cert_file": filepath.Join(root, "cert.pem"), "pem_key_file": filepath.Join(root, "key.pem"), "cmd": "fixture-reload"}}, nil)
			if (err != nil) != failed {
				t.Fatal("reload outcome mismatch", err)
			}
			for _, file := range []struct {
				name, want string
				mode       os.FileMode
			}{{"cert.pem", chain, 0644}, {"key.pem", key, 0600}} {
				raw, e := os.ReadFile(filepath.Join(root, file.name))
				if e != nil || string(raw) != file.want {
					t.Fatal("SFTP content mismatch", file.name, e)
				}
				stat, e := os.Stat(filepath.Join(root, file.name))
				if e != nil || stat.Mode().Perm() != file.mode {
					t.Fatal("SFTP permissions mismatch", file.name, e)
				}
			}
			if len(info["written_paths"].([]string)) != 2 {
				t.Fatal("SFTP completed paths missing")
			}
			remote.mu.Lock()
			defer remote.mu.Unlock()
			if len(remote.commands) != 1 || remote.commands[0] != "fixture-reload" {
				t.Fatal("SSH reload command mismatch")
			}
		})
	}
}
func TestFnOSDeploymentWireInventoryStdinAndServiceSequence(t *testing.T) {
	chain, key := deployFixture(t)
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("write_failed_%t", failed), func(t *testing.T) {
			remote := newSSHWireFixture(t, failed)
			provider, err := New("fnos", remote.config(), Options{RemoteAllowedDirectories: []string{"/fixture"}, Now: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = provider.Deploy(ctx, chain, key, Target{Domains: []string{"example.com"}}, nil)
			if (err != nil) != failed {
				t.Fatal("fnOS write outcome mismatch", err)
			}
			remote.mu.Lock()
			defer remote.mu.Unlock()
			if failed {
				if len(remote.commands) != 2 || len(remote.bodies) != 1 || string(remote.bodies[0]) != chain {
					t.Fatal("fnOS continued after failed write")
				}
				return
			}
			if len(remote.commands) != 7 || len(remote.bodies) != 2 || string(remote.bodies[0]) != chain || string(remote.bodies[1]) != key {
				t.Fatal("fnOS inventory/write/sql/reload sequence mismatch", len(remote.commands))
			}
			for n, service := range []string{"webdav.service", "smbftpd.service", "trim_nginx.service"} {
				if remote.commands[n+4] != "sudo -n systemctl restart "+service {
					t.Fatal("fnOS service sequence mismatch")
				}
			}
		})
	}
}

func TestFTPDeploymentWireTemporaryUploadRenameAndLostReceipt(t *testing.T) {
	chain, key := deployFixture(t)
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprintf("lost_rename_receipt_%t", lost), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var mu sync.Mutex
			files := map[string][]byte{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				socket, e := listener.Accept()
				if e != nil {
					return
				}
				defer socket.Close()
				reader := bufio.NewReader(socket)
				reply := func(code int, message string) { fmt.Fprintf(socket, "%d %s\r\n", code, message) }
				reply(220, "fixture ready")
				var passive net.Listener
				var from string
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
					command := parts[0]
					arg := ""
					if len(parts) > 1 {
						arg = parts[1]
					}
					switch command {
					case "USER":
						if arg != "fixture-user" {
							t.Error("FTP username mismatch")
						}
						reply(331, "password required")
					case "PASS":
						if arg != "fixture-secret" {
							t.Error("FTP password mismatch")
						}
						reply(230, "logged in")
					case "FEAT":
						reply(500, "no extensions")
					case "TYPE", "OPTS":
						reply(200, "accepted")
					case "EPSV":
						passive, e = net.Listen("tcp", "127.0.0.1:0")
						if e != nil {
							t.Error(e)
							return
						}
						_, port, _ := net.SplitHostPort(passive.Addr().String())
						reply(229, "Entering Extended Passive Mode (|||"+port+"|)")
					case "STOR":
						if !strings.HasPrefix(arg, "/fixture/") || !strings.Contains(arg, ".dnsmgr-") {
							t.Error("FTP did not stage a temporary confined path")
						}
						reply(150, "open data")
						data, e := passive.Accept()
						passive.Close()
						if e != nil {
							t.Error(e)
							return
						}
						raw, e := io.ReadAll(data)
						data.Close()
						if e != nil {
							t.Error(e)
							return
						}
						mu.Lock()
						files[arg] = raw
						mu.Unlock()
						reply(226, "stored")
					case "RNFR":
						from = arg
						reply(350, "rename destination required")
					case "RNTO":
						mu.Lock()
						files[arg] = files[from]
						delete(files, from)
						mu.Unlock()
						if lost {
							return
						}
						reply(250, "renamed")
					case "DELE":
						mu.Lock()
						delete(files, arg)
						mu.Unlock()
						reply(250, "deleted")
					case "QUIT":
						reply(221, "bye")
						return
					default:
						t.Errorf("unexpected FTP command %s", command)
						reply(500, "unsupported")
					}
				}
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			if _, e := strconv.Atoi(port); e != nil {
				t.Fatal(e)
			}
			provider, err := New("ftp", map[string]string{"host": host, "port": port, "username": "fixture-user", "password": "fixture-secret"}, Options{RemoteAllowedDirectories: []string{"/fixture"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = provider.Deploy(ctx, chain, key, Target{Config: map[string]string{"format": "pem", "pem_cert_file": "/fixture/cert.pem", "pem_key_file": "/fixture/key.pem"}}, nil)
			if (err != nil) != lost {
				t.Fatal("FTP lost receipt outcome mismatch", err)
			}
			<-done
			mu.Lock()
			defer mu.Unlock()
			if string(files["/fixture/cert.pem"]) != chain {
				t.Fatal("FTP certificate bytes mismatch")
			}
			if lost {
				if files["/fixture/key.pem"] != nil {
					t.Fatal("FTP continued after unconfirmed rename")
				}
			} else if string(files["/fixture/key.pem"]) != key || len(files) != 2 {
				t.Fatal("FTP key bytes or temporary cleanup mismatch")
			}
		})
	}
}
