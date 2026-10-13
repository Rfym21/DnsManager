package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func Client(proxyURL string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.MaxIdleConnsPerHost = 10
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil || u.Hostname() == "" || u.Port() == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, errors.New("代理地址格式不正确")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("代理端口不正确")
		}
		switch u.Scheme {
		case "http", "https":
			t.Proxy = http.ProxyURL(u)
		case "socks5", "socks5h":
			var auth *proxy.Auth
			if u.User != nil {
				password, _ := u.User.Password()
				auth = &proxy.Auth{User: u.User.Username(), Password: password}
			}
			d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: timeout})
			if err != nil {
				return nil, errors.New("SOCKS5配置不正确")
			}
			cd, ok := d.(proxy.ContextDialer)
			if !ok {
				return nil, errors.New("SOCKS5 context dial unsupported")
			}
			t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if u.Scheme == "socks5" {
					resolved, e := resolveAddress(ctx, address, false)
					if e != nil {
						return nil, e
					}
					address = resolved
				}
				return cd.DialContext(ctx, network, address)
			}
		case "socks4", "socks4a":
			t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialSOCKS4(ctx, u, address, timeout)
			}
		default:
			return nil, errors.New("不支持的代理协议")
		}
	}
	return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || !strings.EqualFold(req.URL.Host, via[0].URL.Host)) {
			return errors.New("跨主机重定向已拒绝")
		}
		return nil
	}}, nil
}
func resolveAddress(ctx context.Context, address string, ipv4 bool) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) != nil {
		return address, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", errors.New("代理目标解析失败")
	}
	for _, ip := range ips {
		if !ipv4 || ip.IP.To4() != nil {
			return net.JoinHostPort(ip.IP.String(), port), nil
		}
	}
	return "", errors.New("代理目标没有可用地址")
}
func dialSOCKS4(ctx context.Context, u *url.URL, address string, timeout time.Duration) (net.Conn, error) {
	host, portRaw, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	remote := false
	if ip == nil {
		if u.Scheme == "socks4a" {
			ip = net.IPv4(0, 0, 0, 1).To4()
			remote = true
		} else {
			resolved, e := resolveAddress(ctx, address, true)
			if e != nil {
				return nil, e
			}
			hostResolved, _, _ := net.SplitHostPort(resolved)
			ip = net.ParseIP(hostResolved).To4()
		}
	}
	if ip == nil {
		return nil, errors.New("SOCKS4需要IPv4目标")
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, errors.New("代理连接失败")
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	user := ""
	if u.User != nil {
		user = u.User.Username()
	}
	if strings.ContainsRune(user, 0) || strings.ContainsRune(host, 0) {
		return nil, errors.New("SOCKS4身份格式不正确")
	}
	req := []byte{4, 1, 0, 0, ip[0], ip[1], ip[2], ip[3]}
	binary.BigEndian.PutUint16(req[2:4], uint16(port))
	req = append(req, []byte(user)...)
	req = append(req, 0)
	if remote {
		req = append(req, []byte(host)...)
		req = append(req, 0)
	}
	if _, err = conn.Write(req); err != nil {
		return nil, errors.New("代理握手失败")
	}
	response := make([]byte, 8)
	if _, err = io.ReadFull(conn, response); err != nil || response[1] != 90 {
		return nil, errors.New("SOCKS4代理拒绝连接")
	}
	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}
