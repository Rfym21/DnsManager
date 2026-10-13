package automation

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/transport"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ProbeSpec struct {
	Protocol       string `json:"probe"`
	Target         string `json:"target"`
	Port           int    `json:"port,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	TLSVerify      *bool  `json:"tls_verify,omitempty"`
	Host           string `json:"host,omitempty"`
	ExpectedStatus int    `json:"expected_status,omitempty"`
	ExpectedBody   string `json:"expected_body,omitempty"`
	ConnectIP      string `json:"connect_ip,omitempty"`
	ProxyURL       string `json:"proxy_url,omitempty"`
	Proxy          bool   `json:"proxy,omitempty"`
}
type ProbeResult struct {
	Healthy    bool      `json:"healthy"`
	LatencyMS  int64     `json:"latency_ms"`
	CheckedAt  time.Time `json:"checked_at"`
	Error      string    `json:"error,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
}

func Probe(ctx context.Context, p ProbeSpec) (result ProbeResult) {
	started := time.Now()
	result.CheckedAt = started.UTC()
	defer func() { result.LatencyMS = time.Since(started).Milliseconds() }()
	seconds := p.TimeoutSeconds
	if seconds < 1 {
		seconds = 3
	}
	if seconds > 60 {
		seconds = 60
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	fail := func(err error) ProbeResult { result.Error = safeError(err); return result }
	switch p.Protocol {
	case "tcp":
		if p.Port < 1 || p.Port > 65535 {
			return fail(errors.New("invalid TCP port"))
		}
		host := p.Target
		if p.ConnectIP != "" {
			host = p.ConnectIP
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(p.Port)))
		if err != nil {
			return fail(err)
		}
		conn.Close()
		result.Healthy = true
	case "http":
		target, err := url.Parse(p.Target)
		if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
			return fail(errors.New("HTTP probe requires an http(s) URL"))
		}
		client, err := transport.Client(p.ProxyURL, time.Duration(seconds)*time.Second)
		if err != nil {
			return fail(err)
		}
		httpTransport := client.Transport.(*http.Transport)
		httpTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if p.TLSVerify != nil && !*p.TLSVerify {
			httpTransport.TLSClientConfig.InsecureSkipVerify = true
		} // administrator-controlled legacy option
		if p.ConnectIP != "" && net.ParseIP(target.Hostname()) == nil {
			ip := p.ConnectIP
			if net.ParseIP(ip) == nil {
				ips, e := net.DefaultResolver.LookupIPAddr(ctx, ip)
				if e != nil || len(ips) == 0 {
					return fail(errors.New("检测目标IP解析失败"))
				}
				ip = ips[0].IP.String()
			}
			if p.ProxyURL != "" {
				return fail(errors.New("固定IP检测需要直连，请为代理检测使用独立URL"))
			}
			dial := httpTransport.DialContext
			httpTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, e := net.SplitHostPort(address)
				if e != nil {
					return nil, e
				}
				if strings.EqualFold(host, target.Hostname()) {
					address = net.JoinHostPort(ip, port)
				}
				return dial(ctx, network, address)
			}
		}
		defer httpTransport.CloseIdleConnections()
		client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
				return errors.New("invalid redirect scheme")
			}
			if r.URL.Hostname() != target.Hostname() {
				return errors.New("cross-host redirects require a separate probe")
			}
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, "GET", p.Target, nil)
		if err != nil {
			return fail(err)
		}
		if p.Host != "" {
			req.Host = p.Host
		}
		res, err := client.Do(req)
		if err != nil {
			return fail(err)
		}
		defer res.Body.Close()
		result.StatusCode = res.StatusCode
		body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if err != nil {
			return fail(err)
		}
		expected := p.ExpectedStatus
		good := res.StatusCode >= 200 && res.StatusCode < 400
		if expected > 0 {
			good = res.StatusCode == expected
		}
		if !good {
			return fail(fmt.Errorf("HTTP status %d", res.StatusCode))
		}
		if p.ExpectedBody != "" && !strings.Contains(string(body), p.ExpectedBody) {
			return fail(errors.New("response does not contain expected text"))
		}
		result.Healthy = true
	case "icmp":
		host := p.Target
		if p.ConnectIP != "" {
			host = p.ConnectIP
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = errors.New("no address for ICMP probe")
			}
			return fail(err)
		}
		ip := ips[0]
		for _, candidate := range ips {
			if candidate.To4() != nil {
				ip = candidate
				break
			}
		}
		network, address, protocol := "udp4", "0.0.0.0", 1
		var echoType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
		if ip.To4() == nil {
			network, address, protocol = "udp6", "::", 58
			echoType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
		}
		conn, err := icmp.ListenPacket(network, address)
		if err != nil {
			return fail(errors.New("ICMP unavailable; configure ping socket permissions or use TCP/HTTP"))
		}
		defer conn.Close()
		deadline, _ := ctx.Deadline()
		conn.SetDeadline(deadline)
		payload := []byte(fmt.Sprintf("dnsmgr-probe:%d", time.Now().UnixNano()))
		msg := icmp.Message{Type: echoType, Code: 0, Body: &icmp.Echo{ID: int(time.Now().UnixNano() & 0xffff), Seq: 1, Data: payload}}
		data, err := msg.Marshal(nil)
		if err != nil {
			return fail(err)
		}
		if _, err = conn.WriteTo(data, &net.UDPAddr{IP: ip}); err != nil {
			return fail(err)
		}
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return fail(err)
			}
			reply, err := icmp.ParseMessage(protocol, buf[:n])
			if err != nil || reply.Type != replyType {
				continue
			}
			echo, ok := reply.Body.(*icmp.Echo)
			remote, okPeer := peer.(*net.UDPAddr)
			if ok && okPeer && remote.IP.Equal(ip) && echo.Seq == 1 && bytes.Equal(echo.Data, payload) {
				break
			}
		}
		result.Healthy = true
	default:
		return fail(errors.New("unsupported probe protocol"))
	}
	return result
}
