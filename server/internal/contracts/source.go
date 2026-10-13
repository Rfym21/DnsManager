package contracts

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type handlerSource struct {
	Request Schema
	Queries []string
	Errors  map[string][]string
}

// Read the concrete types passed to decode from the real handlers. Changing a
// request field changes both generated contracts; no duplicate Go request DTOs.
func sources(root string, r *registry) (map[string]handlerSource, error) {
	files, err := filepath.Glob(filepath.Join(root, "server/internal/httpapi/*.go"))
	if err != nil {
		return nil, err
	}
	out := map[string]handlerSource{}
	declarations := map[string]ast.Expr{}
	parsed := make([]*ast.File, 0, len(files))
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, file)
		for _, decl := range file.Decls {
			if group, ok := decl.(*ast.GenDecl); ok && group.Tok == token.TYPE {
				for _, spec := range group.Specs {
					if named, ok := spec.(*ast.TypeSpec); ok {
						declarations[named.Name.Name] = named.Type
					}
				}
			}
		}
	}
	for _, file := range parsed {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			source := handlerSource{Errors: map[string][]string{}}
			variables := map[string]ast.Expr{}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if v, ok := node.(*ast.ValueSpec); ok && v.Type != nil {
					for _, name := range v.Names {
						variables[name.Name] = v.Type
					}
				}
				return true
			})
			var parseErr error
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if selector.Sel.Name == "decode" && len(call.Args) == 3 {
					if pointer, ok := call.Args[2].(*ast.UnaryExpr); ok {
						if id, ok := pointer.X.(*ast.Ident); ok && variables[id.Name] != nil {
							source.Request, parseErr = expressionSchema(variables[id.Name], r, declarations, map[string]bool{})
						}
					}
				}
				if selector.Sel.Name == "Get" && len(call.Args) == 1 {
					if inner, ok := selector.X.(*ast.CallExpr); ok {
						if query, ok := inner.Fun.(*ast.SelectorExpr); ok && query.Sel.Name == "Query" {
							if name, ok := literalString(call.Args[0]); ok {
								source.Queries = append(source.Queries, name)
							}
						}
					}
				}
				if selector.Sel.Name == "fail" && len(call.Args) == 5 {
					status, code := "", ""
					if value, ok := call.Args[2].(*ast.BasicLit); ok {
						status = value.Value
					}
					code, _ = literalString(call.Args[3])
					if status != "" && code != "" {
						source.Errors[status] = append(source.Errors[status], code)
					}
				}
				return true
			})
			if parseErr != nil {
				return nil, fmt.Errorf("%s: %w", fn.Name.Name, parseErr)
			}
			out[fn.Name.Name] = source
		}
	}
	return out, nil
}
func literalString(expr ast.Expr) (string, bool) {
	value, ok := expr.(*ast.BasicLit)
	if !ok || value.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(value.Value)
	return s, err == nil
}
func expressionSchema(expr ast.Expr, r *registry, declarations map[string]ast.Expr, resolving map[string]bool) (Schema, error) {
	switch t := expr.(type) {
	case *ast.Ident:
		switch t.Name {
		case "string":
			return scalar("string"), nil
		case "bool":
			return scalar("boolean"), nil
		case "int", "int64", "uint64":
			return scalar("integer"), nil
		case "any":
			return ref("JSONValue"), nil
		case "Grant":
			return ref("Grant"), nil
		default:
			if declaration, ok := declarations[t.Name]; ok && !resolving[t.Name] {
				resolving[t.Name] = true
				schema, err := expressionSchema(declaration, r, declarations, resolving)
				delete(resolving, t.Name)
				return schema, err
			}
			return nil, fmt.Errorf("unregistered request type %s", t.Name)
		}
	case *ast.SelectorExpr:
		packageName, ok := t.X.(*ast.Ident)
		if !ok {
			return nil, fmt.Errorf("unsupported selector")
		}
		name := packageName.Name + "." + t.Sel.Name
		mapping := map[string]string{"dns.Record": "DNSRecord", "json.RawMessage": "JSONValue", "time.Time": "DateTime"}
		if target, ok := mapping[name]; ok {
			return ref(target), nil
		}
		return nil, fmt.Errorf("unregistered request type %s", name)
	case *ast.StarExpr:
		item, err := expressionSchema(t.X, r, declarations, resolving)
		return nullable(item), err
	case *ast.ArrayType:
		item, err := expressionSchema(t.Elt, r, declarations, resolving)
		return nullable(array(item)), err
	case *ast.MapType:
		item, err := expressionSchema(t.Value, r, declarations, resolving)
		return nullable(dict(item)), err
	case *ast.StructType:
		properties := map[string]Schema{}
		for _, field := range t.Fields.List {
			tag := ""
			if field.Tag != nil {
				v, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					return nil, err
				}
				tag = reflect.StructTag(v).Get("json")
			}
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			if name == "" && len(field.Names) > 0 {
				name = field.Names[0].Name
			}
			value, err := expressionSchema(field.Type, r, declarations, resolving)
			if err != nil {
				return nil, err
			}
			properties[name] = value
		}
		// Fields without a validation requirement can be omitted: decode fills Go
		// zero values. Explicit handler requirements are applied by Document.
		return object(properties), nil
	default:
		return nil, fmt.Errorf("unsupported AST request type %T", expr)
	}
}
