package contracts

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Schema is JSON Schema 2020-12, as used by OpenAPI 3.1.
type Schema map[string]any

func ref(name string) Schema    { return Schema{"$ref": "#/components/schemas/" + name} }
func scalar(kind string) Schema { return Schema{"type": kind} }
func array(item Schema) Schema  { return Schema{"type": "array", "items": item} }
func dict(item Schema) Schema   { return Schema{"type": "object", "additionalProperties": item} }
func nullable(s Schema) Schema  { return Schema{"anyOf": []Schema{s, scalar("null")}} }
func object(properties map[string]Schema, required ...string) Schema {
	s := Schema{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func enumeration(values ...string) Schema { return Schema{"type": "string", "enum": values} }
func described(s Schema, description string) Schema {
	copy := Schema{}
	for key, value := range s {
		copy[key] = value
	}
	copy["description"] = description
	return copy
}
func list(item Schema) Schema { return object(map[string]Schema{"items": array(item)}, "items") }
func paged(item Schema) Schema {
	return object(map[string]Schema{"items": array(item), "pagination": ref("Pagination")}, "items", "pagination")
}

type registry struct {
	Schemas map[string]Schema
	names   map[reflect.Type]string
}

func newRegistry() *registry {
	r := &registry{Schemas: map[string]Schema{}, names: map[reflect.Type]string{}}
	r.Schemas["JSONValue"] = Schema{"description": "Extensible vendor metadata and redacted execution details; only JSON-compatible values are accepted.", "anyOf": []Schema{scalar("null"), scalar("boolean"), scalar("number"), scalar("string"), array(ref("JSONValue")), dict(ref("JSONValue"))}}
	r.Schemas["JSONObject"] = described(dict(ref("JSONValue")), "A JSON object containing provider-specific configuration or redacted metadata.")
	return r
}
func (r *registry) register(name string, value any) Schema {
	t := reflect.TypeOf(value)
	if prior, ok := r.names[t]; ok {
		return ref(prior)
	}
	r.names[t] = name
	r.Schemas[name] = r.structSchema(t)
	return ref(name)
}
func (r *registry) typeSchema(t reflect.Type) Schema {
	if t == reflect.TypeOf(time.Time{}) {
		return Schema{"type": "string", "format": "date-time"}
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return ref("JSONValue")
	}
	if name, ok := r.names[t]; ok {
		return ref(name)
	}
	switch t.Kind() {
	case reflect.Pointer:
		return nullable(r.typeSchema(t.Elem()))
	case reflect.Struct:
		return r.structSchema(t)
	case reflect.String:
		return scalar("string")
	case reflect.Bool:
		return scalar("boolean")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return scalar("integer")
	case reflect.Float32, reflect.Float64:
		return scalar("number")
	case reflect.Slice:
		return nullable(array(r.typeSchema(t.Elem())))
	case reflect.Array:
		return array(r.typeSchema(t.Elem()))
	case reflect.Map:
		return nullable(dict(r.typeSchema(t.Elem())))
	case reflect.Interface:
		return ref("JSONValue")
	default:
		panic(fmt.Sprintf("unsupported contract type: %s", t))
	}
}
func (r *registry) structSchema(t reflect.Type) Schema {
	properties := map[string]Schema{}
	required := []string{}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		if field.Anonymous && parts[0] == "" {
			embedded := r.structSchema(field.Type)
			for key, value := range embedded["properties"].(map[string]Schema) {
				properties[key] = value
			}
			if names, ok := embedded["required"].([]string); ok {
				required = append(required, names...)
			}
			continue
		}
		name := parts[0]
		if name == "" {
			name = field.Name
		}
		properties[name] = r.typeSchema(field.Type)
		if !strings.Contains(tag, ",omitempty") {
			required = append(required, name)
		}
	}
	return object(properties, required...)
}
