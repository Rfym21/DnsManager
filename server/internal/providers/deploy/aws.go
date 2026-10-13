package deploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type awsProvider struct{ *httpProvider }

func (p *awsProvider) requestAWS(ctx context.Context, service, method, path string, body []byte, headers map[string]string) ([]byte, http.Header, error) {
	endpoint := map[string]string{"iam": "https://iam.amazonaws.com", "acm": "https://acm.us-east-1.amazonaws.com", "cloudfront": "https://cloudfront.amazonaws.com"}[service]
	if p.cfg["url"] != "" {
		endpoint = p.base
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(body))
	if e != nil {
		return nil, nil, e
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	signAWS(req, body, p.cfg["AccessKeyId"], p.cfg["SecretAccessKey"], "us-east-1", service, p.opts)
	resp, e := p.client.Do(req)
	if e != nil {
		return nil, nil, e
	}
	defer resp.Body.Close()
	raw, e := readLimited(resp.Body)
	if e != nil {
		return nil, nil, e
	}
	if resp.StatusCode/100 != 2 {
		return nil, nil, rejectedHTTP("AWS "+service, resp.StatusCode, "provider request failed")
	}
	return raw, resp.Header, nil
}
func (p *awsProvider) acm(ctx context.Context, action string, body map[string]any) (map[string]any, error) {
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	data, _, e := p.requestAWS(ctx, "acm", http.MethodPost, "/", raw, map[string]string{"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "CertificateManager." + action})
	if e != nil {
		return nil, e
	}
	var m map[string]any
	if e = json.Unmarshal(data, &m); e != nil {
		return nil, errors.New("invalid AWS ACM JSON")
	}
	return m, nil
}
func (p *awsProvider) Validate(ctx context.Context) error {
	if p.cfg["AccessKeyId"] == "" || p.cfg["SecretAccessKey"] == "" {
		return errors.New("AWS credentials are required")
	}
	_, _, e := p.requestAWS(ctx, "iam", http.MethodGet, "/?Action=GetUser&Version=2010-05-08", nil, nil)
	return e
}
func (p *awsProvider) Deploy(ctx context.Context, chain, key string, target Target, prior Info) (Info, error) {
	info := cloneInfo(prior)
	parsed, _, _, parseErr := parsePair(chain, key)
	if parseErr != nil {
		return info, parseErr
	}
	info = renewedInfo(prior, sha256hex(parsed.Raw), "cert_id")
	leaf, rest, e := splitChain(chain)
	if e != nil {
		return info, e
	}
	arn := target.Config["acm_arn"]
	product := target.Config["product"]
	if product == "acm" && arn == "" {
		return info, errors.New("ACM ARN is required")
	}
	if arn == "" {
		arn = text(info["cert_id"])
	}
	body := map[string]any{"Certificate": base64.StdEncoding.EncodeToString([]byte(leaf)), "PrivateKey": base64.StdEncoding.EncodeToString([]byte(key))}
	if rest != "" {
		body["CertificateChain"] = base64.StdEncoding.EncodeToString([]byte(rest))
	}
	if arn != "" {
		body["CertificateArn"] = arn
	}
	result, e := p.acm(ctx, "ImportCertificate", body)
	if e != nil {
		return info, e
	}
	created := text(result["CertificateArn"])
	if created == "" {
		return info, errors.New("ACM import returned no ARN")
	}
	if created != arn {
		info["cert_id"] = created
		if e = persist(ctx, p.opts, info); e != nil {
			return info, e
		}
	}
	arn = created
	if product == "acm" {
		return info, nil
	}
	if product != "" && product != "cloudfront" {
		return info, errors.New("invalid AWS deployment product")
	}
	distribution := target.Config["distribution_id"]
	if distribution == "" {
		return info, errors.New("CloudFront distribution ID is required")
	}
	path := "/2020-05-31/distribution/" + url.PathEscape(distribution) + "/config"
	raw, headers, e := p.requestAWS(ctx, "cloudfront", http.MethodGet, path, nil, nil)
	if e != nil {
		return info, e
	}
	etag := headers.Get("ETag")
	if etag == "" {
		return info, errors.New("CloudFront response omitted ETag")
	}
	node, e := parseXMLTree(raw)
	if e != nil {
		return info, e
	}
	viewer := node.child("ViewerCertificate")
	if viewer == nil {
		viewer = &xmlNode{Name: xml.Name{Local: "ViewerCertificate"}}
		node.Children = append(node.Children, viewer)
	}
	viewer.remove("Certificate", "CertificateSource", "IAMCertificateId")
	viewer.set("ACMCertificateArn", arn)
	viewer.set("CloudFrontDefaultCertificate", "false")
	if viewer.child("SSLSupportMethod") == nil {
		viewer.set("SSLSupportMethod", "sni-only")
	}
	if viewer.child("MinimumProtocolVersion") == nil {
		viewer.set("MinimumProtocolVersion", "TLSv1.2_2021")
	}
	updated, e := xml.Marshal(node)
	if e != nil {
		return info, e
	}
	_, _, e = p.requestAWS(ctx, "cloudfront", http.MethodPut, path, updated, map[string]string{"If-Match": etag, "Content-Type": "application/xml"})
	return info, e
}

type xmlNode struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Text     string
	Children []*xmlNode
}

func parseXMLTree(raw []byte) (*xmlNode, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var root *xmlNode
	stack := []*xmlNode{}
	for {
		token, e := decoder.Token()
		if e != nil {
			if root != nil && len(stack) == 0 {
				return root, nil
			}
			return nil, errors.New("invalid CloudFront configuration XML")
		}
		switch t := token.(type) {
		case xml.StartElement:
			n := &xmlNode{Name: t.Name, Attrs: t.Attr}
			if len(stack) == 0 {
				root = n
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("invalid XML end element")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		}
	}
}
func (n *xmlNode) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = n.Name
	start.Attr = n.Attrs
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if strings.TrimSpace(n.Text) != "" {
		if err := e.EncodeToken(xml.CharData(n.Text)); err != nil {
			return err
		}
	}
	for _, child := range n.Children {
		if err := e.Encode(child); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}
func (n *xmlNode) child(name string) *xmlNode {
	for _, child := range n.Children {
		if child.Name.Local == name {
			return child
		}
	}
	return nil
}
func (n *xmlNode) set(name, value string) {
	child := n.child(name)
	if child == nil {
		child = &xmlNode{Name: xml.Name{Local: name}}
		n.Children = append(n.Children, child)
	}
	child.Text = value
	child.Children = nil
}
func (n *xmlNode) remove(names ...string) {
	children := []*xmlNode{}
	for _, child := range n.Children {
		drop := false
		for _, name := range names {
			if child.Name.Local == name {
				drop = true
			}
		}
		if !drop {
			children = append(children, child)
		}
	}
	n.Children = children
}
