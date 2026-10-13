package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/dns-manager/dnsmgr/server/internal/automation"
	certprovider "github.com/dns-manager/dnsmgr/server/internal/providers/cert"
	"github.com/dns-manager/dnsmgr/server/internal/store"
	"github.com/go-chi/chi/v5"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func (a *API) certificateDownload(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	o, err := a.Store.Object(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		a.internal(w, r, err)
		return
	}
	if o.Kind != "certificates" {
		a.fail(w, r, 404, "not_found", "证书不存在")
		return
	}
	var d automation.CertificateData
	if err = json.Unmarshal(o.Data, &d); err != nil {
		a.internal(w, r, err)
		return
	}
	var req struct {
		Format   string `json:"format"`
		Password string `json:"password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	content := ""
	filename := "certificate.pem"
	binary := false
	switch req.Format {
	case "pem", "crt", "fullchain":
		content = d.Fullchain
	case "key":
		content = d.PrivateKey
		filename = "privatekey.pem"
	case "pfx":
		b, e := certificatePFX(d.Fullchain, d.PrivateKey, req.Password)
		if e != nil {
			a.fail(w, r, 400, "pfx_failed", e.Error())
			return
		}
		content = base64.StdEncoding.EncodeToString(b)
		filename = "certificate.pfx"
		binary = true
	default:
		a.fail(w, r, 400, "invalid_format", "下载格式不正确")
		return
	}
	if content == "" {
		a.fail(w, r, 409, "certificate_unavailable", "证书尚未签发")
		return
	}
	if err = a.Store.Audit(r.Context(), principal(r).User.ID, "certificate.download", "certificate", o.ID, "", "", map[string]string{"format": req.Format}); err != nil {
		a.internal(w, r, err)
		return
	}
	send(w, 200, map[string]any{"content": content, "filename": filename, "base64": binary})
}
func certificatePFX(chain, key, password string) ([]byte, error) {
	parsedKey, err := certprovider.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	certs := []*x509.Certificate{}
	remain := []byte(chain)
	for len(remain) > 0 {
		block, rest := pem.Decode(remain)
		if block == nil {
			break
		}
		remain = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	if _, err = certprovider.ParseResult(chain, key); err != nil {
		return nil, err
	}
	return pkcs12.Modern.Encode(parsedKey, certs[0], certs[1:], password)
}
func (a *API) certificateImport(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	var req struct {
		Name       string `json:"name"`
		Fullchain  string `json:"fullchain"`
		PrivateKey string `json:"private_key"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	result, err := certprovider.ParseResult(req.Fullchain, req.PrivateKey)
	if err != nil {
		a.fail(w, r, 400, "invalid_certificate", err.Error())
		return
	}
	block, _ := pem.Decode([]byte(req.Fullchain))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		a.fail(w, r, 400, "invalid_certificate", err.Error())
		return
	}
	data := automation.CertificateData{Domains: leaf.DNSNames, Status: "issued", Fullchain: result.Fullchain, PrivateKey: result.PrivateKey, Issuer: result.Issuer, NotBefore: result.NotBefore, NotAfter: result.NotAfter, Fingerprint: result.Fingerprint}
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		data.KeyType = "rsa"
		data.KeySize = key.N.BitLen()
	case *ecdsa.PublicKey:
		data.KeyType = "ecdsa"
		data.KeySize = key.Curve.Params().BitSize
	}
	if req.Name == "" {
		req.Name = strings.Join(leaf.DNSNames, ", ")
	}
	raw, _ := json.Marshal(data)
	o, err := a.Store.SaveObject(r.Context(), store.Object{Kind: "certificates", Name: req.Name, OwnerID: principal(r).User.ID, Data: raw, Active: true}, true)
	if err != nil {
		a.internal(w, r, err)
		return
	}
	o.Data = redactJSON(o.Data)
	send(w, 201, o)
}
