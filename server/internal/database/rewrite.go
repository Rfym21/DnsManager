package database

import (
	"fmt"
	"regexp"
	"strings"
)

var insertTable = regexp.MustCompile(`(?i)^\s*INSERT\s+(?:IGNORE\s+)?INTO\s+([a-z_]+)`)
var boundedDelete = regexp.MustCompile(`(?is)^\s*DELETE FROM ([a-z_]+) WHERE (.*) LIMIT ([0-9]+)\s*$`)
var rowLock = regexp.MustCompile(`(?i)\s+FOR UPDATE(?: SKIP LOCKED)?`)
var booleanMembership = regexp.MustCompile(`(?i)\bIN\s*\(`)
var interval = regexp.MustCompile(`(?is)^INTERVAL\s+(.+)\s+(SECOND|MINUTE|HOUR|DAY)$`)
var primaryKeys = map[string]string{"settings": "name", "login_attempts": "attempt_key", "job_items": "job_id,item_index", "object_schedule_state": "object_id", "worker_heartbeats": "worker_id"}

// Rewrite converts application SQL while leaving quoted strings untouched.
// Native schema SQL is sent directly through Raw and is never rewritten.
func Rewrite(d Dialect, query string) string {
	if d == MySQL {
		return query
	}
	q := query
	if match := insertTable.FindStringSubmatch(q); len(match) > 0 {
		table := match[1]
		upper := strings.ToUpper(maskQuoted(q))
		if at := strings.Index(upper, " ON DUPLICATE KEY UPDATE "); at >= 0 {
			updates := q[at+len(" ON DUPLICATE KEY UPDATE "):]
			updates = functions(updates, func(name string, args []string) string {
				if strings.EqualFold(name, "VALUES") {
					return "excluded." + args[0]
				}
				return name + "(" + strings.Join(args, ",") + ")"
			})
			updates = qualifyUpdates(updates, table)
			q = q[:at] + " ON CONFLICT (" + primaryKeys[strings.ToLower(table)] + ") DO UPDATE SET " + updates
		} else if strings.Contains(upper, "INSERT IGNORE INTO") {
			q = strings.Replace(q, q[:strings.Index(upper, "INTO")], "INSERT ", 1) + " ON CONFLICT DO NOTHING"
		}
	}
	q = functions(q, func(name string, args []string) string {
		switch strings.ToUpper(name) {
		case "UTC_TIMESTAMP":
			if d == PostgreSQL {
				return "clock_timestamp()"
			}
			return "(strftime('%Y-%m-%d %H:%M:%f','now') || '000000')"
		case "DATE_ADD", "DATE_SUB":
			if len(args) == 2 {
				if m := interval.FindStringSubmatch(strings.TrimSpace(args[1])); m != nil {
					sign := "+"
					if strings.EqualFold(name, "DATE_SUB") {
						sign = "-"
					}
					if d == PostgreSQL {
						return "(" + args[0] + " " + sign + " (" + m[1] + ") * INTERVAL '1 " + strings.ToLower(m[2]) + "')"
					}
					return "(strftime('%Y-%m-%d %H:%M:%f'," + args[0] + ", '" + sign + "' || (" + m[1] + ") || ' " + strings.ToLower(m[2]) + "') || '000000')"
				}
			}
		case "IF":
			if len(args) == 3 {
				return "(CASE WHEN " + args[0] + " THEN " + args[1] + " ELSE " + args[2] + " END)"
			}
		case "JSON_OBJECT":
			if d == PostgreSQL {
				return "jsonb_build_object(" + strings.Join(args, ",") + ")"
			}
			return "json_object(" + strings.Join(args, ",") + ")"
		case "CONCAT":
			return "(" + strings.Join(args, " || ") + ")"
		case "GREATEST":
			if d == SQLite {
				return "MAX(" + strings.Join(args, ",") + ")"
			}
		case "SUM":
			if len(args) == 1 && (strings.Contains(args[0], "=") || booleanMembership.MatchString(args[0])) {
				return "SUM(CASE WHEN " + args[0] + " THEN 1 ELSE 0 END)"
			}
		}
		return name + "(" + strings.Join(args, ",") + ")"
	})
	if d == SQLite {
		q = unquoted(q, func(part string) string { return rowLock.ReplaceAllString(part, "") })
	}
	if m := boundedDelete.FindStringSubmatch(q); m != nil {
		id := "ctid"
		if d == SQLite {
			id = "rowid"
		}
		q = "DELETE FROM " + m[1] + " WHERE " + id + " IN (SELECT " + id + " FROM " + m[1] + " WHERE " + m[2] + " LIMIT " + m[3] + ")"
	}
	if d == PostgreSQL {
		n := 0
		q = mapTokens(q, func(token string) string {
			if token == "?" {
				n++
				return fmt.Sprintf("$%d", n)
			}
			if strings.HasPrefix(token, "`") {
				return `"` + strings.Trim(token, "`") + `"`
			}
			return token
		})
	}
	return q
}

// functions walks nested calls and respects literals, identifiers and comments.
func functions(s string, rewrite func(string, []string) string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if end := commentEnd(s, i); end > i {
			out.WriteString(s[i:end])
			i = end
			continue
		}
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			end := quotedEnd(s, i)
			out.WriteString(s[i:end])
			i = end
			continue
		}
		if identifier(s[i]) && (i == 0 || !identifier(s[i-1])) {
			end := i + 1
			for end < len(s) && identifier(s[end]) {
				end++
			}
			paren := end
			for paren < len(s) && s[paren] == ' ' {
				paren++
			}
			if paren < len(s) && s[paren] == '(' {
				close := matching(s, paren)
				if close >= 0 {
					parts := splitArgs(s[paren+1 : close])
					for j := range parts {
						parts[j] = functions(parts[j], rewrite)
					}
					out.WriteString(rewrite(s[i:end], parts))
					i = close + 1
					continue
				}
			}
			out.WriteString(s[i:end])
			i = end
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}
func identifier(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
func quotedEnd(s string, i int) int {
	quote := s[i]
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\\' {
			j++
			continue
		}
		if s[j] == quote {
			if j+1 < len(s) && s[j+1] == quote {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(s)
}
func matching(s string, start int) int {
	depth := 0
	for i := start; i < len(s); i++ {
		if end := commentEnd(s, i); end > i {
			i = end - 1
			continue
		}
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			i = quotedEnd(s, i) - 1
			continue
		}
		if s[i] == '(' {
			depth++
		}
		if s[i] == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
func splitArgs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := []string{}
	last := 0
	for i := 0; i < len(s); i++ {
		if end := commentEnd(s, i); end > i {
			i = end - 1
			continue
		}
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			i = quotedEnd(s, i) - 1
			continue
		}
		if s[i] == '(' {
			i = matching(s, i)
			if i < 0 {
				return []string{s}
			}
			continue
		}
		if s[i] == ',' {
			parts = append(parts, strings.TrimSpace(s[last:i]))
			last = i + 1
		}
	}
	return append(parts, strings.TrimSpace(s[last:]))
}
func mapTokens(s string, fn func(string) string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if end := commentEnd(s, i); end > i {
			out.WriteString(s[i:end])
			i = end
			continue
		}
		end := i + 1
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			end = quotedEnd(s, i)
		} else if identifier(s[i]) {
			for end < len(s) && identifier(s[end]) {
				end++
			}
		}
		out.WriteString(fn(s[i:end]))
		i = end
	}
	return out.String()
}

func commentEnd(s string, i int) int {
	if strings.HasPrefix(s[i:], "--") {
		if n := strings.IndexByte(s[i:], '\n'); n >= 0 {
			return i + n + 1
		}
		return len(s)
	}
	if strings.HasPrefix(s[i:], "/*") {
		if n := strings.Index(s[i+2:], "*/"); n >= 0 {
			return i + n + 4
		}
		return len(s)
	}
	return i
}
func unquoted(s string, fn func(string) string) string {
	var out strings.Builder
	start := 0
	for i := 0; i < len(s); {
		end := commentEnd(s, i)
		if end == i && (s[i] == '\'' || s[i] == '"' || s[i] == '`') {
			end = quotedEnd(s, i)
		}
		if end > i {
			out.WriteString(fn(s[start:i]))
			out.WriteString(s[i:end])
			i = end
			start = i
		} else {
			i++
		}
	}
	out.WriteString(fn(s[start:]))
	return out.String()
}

func maskQuoted(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		end := commentEnd(s, i)
		if end == i && (s[i] == '\'' || s[i] == '"' || s[i] == '`') {
			end = quotedEnd(s, i)
		}
		if end > i {
			out.WriteString(strings.Repeat(" ", end-i))
			i = end
		} else {
			out.WriteByte(s[i])
			i++
		}
	}
	return out.String()
}
func qualifyUpdates(s, table string) string {
	parts := splitArgs(s)
	for i, part := range parts {
		if at := strings.Index(part, "="); at >= 0 {
			left := part[:at+1]
			right := part[at+1:]
			position := 0
			right = mapTokens(right, func(token string) string {
				start := position
				position += len(token)
				if token == "" || !identifier(token[0]) || token[0] >= '0' && token[0] <= '9' {
					return token
				}
				if start > 0 && right[start-1] == '.' || position < len(right) && right[position] == '.' || position < len(right) && right[position] == '(' {
					return token
				}
				switch strings.ToUpper(token) {
				case "IF", "INTERVAL", "SECOND", "MINUTE", "HOUR", "DAY", "NULL", "TRUE", "FALSE", "IN", "AND", "OR", "NOT", "CASE", "WHEN", "THEN", "ELSE", "END":
					return token
				}
				return table + "." + token
			})
			parts[i] = left + right
		}
	}
	return strings.Join(parts, ",")
}
