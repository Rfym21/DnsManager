package notifications

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

func sendSMTP(ctx context.Context, cfg map[string]string, m Message) error {
	from, err := mail.ParseAddress(cfg["from"])
	if err != nil {
		return errors.New("SMTP发件地址无效")
	}
	if cfg["from_name"] != "" {
		from.Name = cfg["from_name"]
	}
	addresses, err := mail.ParseAddressList(strings.ReplaceAll(cfg["to"], ";", ","))
	if err != nil || len(addresses) == 0 {
		return errors.New("SMTP收件地址无效")
	}
	recipients := []string{}
	for _, a := range addresses {
		recipients = append(recipients, a.Address)
	}
	port := cfg["port"]
	if port == "" {
		port = "465"
	}
	host := cfg["host"]
	if host == "" || strings.ContainsAny(host, "\r\n") {
		return errors.New("SMTP主机不能为空")
	}
	mode := cfg["tls_mode"]
	if mode == "" || mode == "auto" {
		mode = "starttls"
		if port == "465" {
			mode = "implicit"
		}
	}
	if mode != "implicit" && mode != "starttls" && mode != "plain" {
		return errors.New("SMTP TLS模式无效")
	}
	address := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if mode == "implicit" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return errors.New("SMTP连接失败")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return errors.New("SMTP握手失败")
	}
	defer client.Close()
	if mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP需要TLS支持")
		}
		if err = client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return errors.New("SMTP TLS握手失败")
		}
	}
	if cfg["username"] != "" {
		if err = client.Auth(smtp.PlainAuth("", cfg["username"], cfg["password"], host)); err != nil {
			return errors.New("SMTP认证失败")
		}
	}
	if err = client.Mail(from.Address); err != nil {
		return errors.New("SMTP发件人被拒绝")
	}
	for _, to := range recipients {
		if err = client.Rcpt(to); err != nil {
			return errors.New("SMTP收件人被拒绝")
		}
	}
	writer, err := client.Data()
	if err != nil {
		return errors.New("SMTP未接受消息")
	}
	title := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(m.Title)) + "?="
	mimeType := "text/plain"
	body := contentText(m.Body, false)
	if cfg["content_format"] == "html" {
		mimeType = "text/html"
		body = m.Body
	}
	text := "From: " + from.String() + "\r\nTo: " + strings.Join(recipients, ", ") + "\r\nSubject: " + title + "\r\nMIME-Version: 1.0\r\nContent-Type: " + mimeType + "; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrapBase64([]byte(body)) + "\r\n"
	if _, err = io.WriteString(writer, text); err != nil {
		return errors.New("SMTP消息写入失败")
	}
	if err = writer.Close(); err != nil {
		return errors.New("SMTP消息被拒绝")
	}
	if err = client.Quit(); err != nil {
		return errors.New("SMTP会话结束失败")
	}
	return nil
}
func wrapBase64(raw []byte) string {
	encoded := base64.StdEncoding.EncodeToString(raw)
	var out strings.Builder
	for len(encoded) > 76 {
		out.WriteString(encoded[:76])
		out.WriteString("\r\n")
		encoded = encoded[76:]
	}
	out.WriteString(encoded)
	return out.String()
}
