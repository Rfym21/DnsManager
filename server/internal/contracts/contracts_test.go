package contracts

import (
	"encoding/json"
	"go/ast"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}
func TestExecutableRouteCoverageAndGeneration(t *testing.T) {
	root := repositoryRoot(t)
	doc, err := Document(root)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := Routes()
	if err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	ids := map[string]bool{}
	for _, route := range routes {
		item, ok := paths[route.Path].(map[string]any)
		if !ok {
			t.Fatalf("uncovered route %s", route.Path)
		}
		op, ok := item[strings.ToLower(route.Method)].(map[string]any)
		if !ok {
			t.Fatalf("uncovered method %s %s", route.Method, route.Path)
		}
		id := op["operationId"].(string)
		if ids[id] {
			t.Fatalf("duplicate operation ID %s", id)
		}
		ids[id] = true
		if op["x-go-handler"] != route.Handler {
			t.Fatalf("handler drift %s", id)
		}
		if _, ok := op["security"]; !ok {
			t.Fatalf("missing security policy %s", id)
		}
		if op["summary"] == "" || len(op["responses"].(map[string]any)) == 0 {
			t.Fatalf("empty operation %s", id)
		}
	}
	if len(ids) != doc["x-route-count"] {
		t.Fatal("route count differs")
	}
	if err := Generate(root, true); err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(doc)
	for i := 0; i < 4; i++ {
		next, err := Document(root)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(next)
		if string(first) != string(raw) {
			t.Fatal("generation is nondeterministic")
		}
	}
}
func TestNoEmptySchemasAndResolvedReferences(t *testing.T) {
	doc, err := Document(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(doc)
	var value map[string]any
	json.Unmarshal(raw, &value)
	schemas := value["components"].(map[string]any)["schemas"].(map[string]any)
	var walk func(any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			if reference, ok := node["$ref"].(string); ok {
				name := strings.TrimPrefix(reference, "#/components/schemas/")
				if _, ok := schemas[name]; !ok {
					t.Fatalf("unresolved reference %s", reference)
				}
			}
			if s, ok := node["schema"].(map[string]any); ok && len(s) == 0 {
				t.Fatal("empty operation schema")
			}
			if node["type"] == "object" {
				p, _ := node["properties"].(map[string]any)
				if len(p) == 0 {
					if _, ok := node["additionalProperties"].(map[string]any); !ok {
						t.Fatalf("untyped empty object: %#v", node)
					}
				}
			}
			for _, child := range node {
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(value)
}
func TestPrivateRuntimeFieldsNeverBecomePublicDTOs(t *testing.T) {
	r := newRegistry()
	catalog(r)
	for name, keys := range map[string][]string{"User": {"password_hash", "totp_secret"}, "Account": {"config"}, "Job": {"payload", "checkpoint", "lease_owner", "token_hash", "submission", "idempotency_key"}} {
		properties := r.Schemas[name]["properties"].(map[string]Schema)
		for _, key := range keys {
			if _, ok := properties[key]; ok {
				t.Fatalf("private field %s.%s exposed", name, key)
			}
		}
	}
	certificate := r.Schemas["CertificateData"]["properties"].(map[string]Schema)
	if certificate["private_key"]["const"] != "" {
		t.Fatal("certificate private key not redacted")
	}
	configuration := r.Schemas["CertificateDataConfiguration"]["properties"].(map[string]Schema)
	if configuration["private_key"]["writeOnly"] != true {
		t.Fatal("manual certificate key needs writeOnly")
	}
	if _, ok := configuration["checkpoint"]; ok {
		t.Fatal("checkpoint is editable through configuration")
	}
	for _, field := range []string{"window", "retry_policy"} {
		if _, ok := r.Schemas["DeploymentDataConfiguration"]["properties"].(map[string]Schema)[field]; !ok {
			t.Fatalf("missing deployment field %s", field)
		}
	}
}
func TestRequestFieldsComeFromHandlerSource(t *testing.T) {
	r := newRegistry()
	catalog(r)
	source, err := sources(repositoryRoot(t), r)
	if err != nil {
		t.Fatal(err)
	}
	for handler, fields := range map[string][]string{"createUser": {"username", "password", "role"}, "updateUser": {"username", "role", "enabled"}, "recordBatch": {"domain_ids", "records", "operation"}, "writeObject": {"name", "domain_id", "data", "active", "version"}, "cfIngress": {"config", "version", "sync_dns"}, "resolveDeploymentJob": {"resolution", "reason"}} {
		properties := source[handler].Request["properties"].(map[string]Schema)
		if len(properties) != len(fields) {
			t.Fatalf("source fields differ %s", handler)
		}
		for _, field := range fields {
			if _, ok := properties[field]; !ok {
				t.Fatalf("source field missing %s.%s", handler, field)
			}
		}
	}
}
func TestNamedRequestDeclarationsRejectUnknownAndRecursiveTypes(t *testing.T) {
	r := newRegistry()
	for _, declarations := range []map[string]ast.Expr{{}, {"request": ast.NewIdent("request")}} {
		if _, err := expressionSchema(ast.NewIdent("request"), r, declarations, map[string]bool{}); err == nil {
			t.Fatal("unknown or recursive request declaration silently accepted")
		}
	}
}
func TestNormalizationAndUnknownRoute(t *testing.T) {
	if got := normalizePath("/api/record/{operation:data|add}/{id}"); got != "/api/record/{operation}/{id}" {
		t.Fatal(got)
	}
	if _, err := specification(Route{Method: "POST", Path: "/unexpected", Handler: "unknown"}, newRegistry()); err == nil {
		t.Fatal("undocumented handler silently accepted")
	}
}

func TestGeneratedFilePermissions(t *testing.T) {
	for _, file := range []string{"server/openapi.json", "web/src/generated/contracts.ts"} {
		info, err := os.Stat(filepath.Join(repositoryRoot(t), file))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0111 != 0 {
			t.Fatalf("contract artifact is executable %s", file)
		}
	}
}
