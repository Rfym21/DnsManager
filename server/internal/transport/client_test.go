package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPProxyAuthorizationAndRedirectBoundary(t *testing.T) {
	seen := make(chan *http.Request, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer proxy.Close()
	client, err := Client(strings.Replace(proxy.URL, "http://", "http://fixture:secret@", 1), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://origin.example.invalid/resource?q=test")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	req := <-seen
	if req.URL.Host != "origin.example.invalid" || req.Header.Get("Proxy-Authorization") == "" {
		t.Fatal("proxy request lost target or auth")
	}
	for _, raw := range []string{"http://host", "ssh://host:22", "http://host:80/path", "http://host:80?token=secret"} {
		if _, err := Client(raw, time.Second); err == nil {
			t.Fatalf("invalid proxy accepted %s", raw)
		}
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example.invalid/", 302)
	}))
	defer origin.Close()
	direct, _ := Client("", time.Second)
	if _, err = direct.Get(origin.URL); err == nil {
		t.Fatal("cross-host redirect accepted")
	}
}

func TestSOCKS4HandshakeAndRejection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		header := make([]byte, 8)
		_, e = io.ReadFull(reader, header)
		if e != nil {
			done <- e
			return
		}
		user, e := reader.ReadString(0)
		if e != nil {
			done <- e
			return
		}
		if header[0] != 4 || header[1] != 1 || binary.BigEndian.Uint16(header[2:4]) != 8080 || user != "fixture\x00" {
			done <- io.ErrUnexpectedEOF
			return
		}
		conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
		request, e := http.ReadRequest(reader)
		if e == nil {
			if request.Host != "127.0.0.1:8080" {
				e = io.ErrUnexpectedEOF
			}
			io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}
		done <- e
	}()
	client, err := Client("socks4://fixture@"+listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Get("http://127.0.0.1:8080/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "ok" {
		t.Fatal(string(body))
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
