// Package dotenv reads KEY=value pairs from .env files so they can be
// moved into the vault.
//
// It understands the common subset: comments, blank lines, an optional
// "export " prefix, single-quoted values (taken literally), double-quoted
// values (with \n, \t, \", \\ escapes, and newlines inside the quotes), and
// unquoted values with trailing " # comments". It does not expand ${VARS}.
package dotenv

import (
	"fmt"
	"strings"
)

// Entry is one variable from the file.
type Entry struct {
	Key   string
	Value string
	Line  int
}

// Parse returns the entries in src in file order. For a key that appears
// more than once, the last value wins, as in most .env loaders.
func Parse(src string) ([]Entry, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	var out []Entry
	index := map[string]int{}
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, rest, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("line %d: expected KEY=value", lineNo)
		}
		rest = strings.TrimLeft(rest, " \t")

		var value string
		switch {
		case strings.HasPrefix(rest, `"`):
			// A double-quoted value may span lines.
			body := rest[1:]
			for !hasClosingQuote(body) {
				if i+1 >= len(lines) {
					return nil, fmt.Errorf("line %d: missing closing \"", lineNo)
				}
				i++
				body += "\n" + lines[i]
			}
			end := closingQuote(body)
			value = unescape(body[:end])
		case strings.HasPrefix(rest, "'"):
			end := strings.Index(rest[1:], "'")
			if end < 0 {
				return nil, fmt.Errorf("line %d: missing closing '", lineNo)
			}
			value = rest[1 : 1+end]
		default:
			if j := strings.Index(rest, " #"); j >= 0 {
				rest = rest[:j]
			}
			value = strings.TrimSpace(rest)
		}

		if j, seen := index[key]; seen {
			out[j] = Entry{Key: key, Value: value, Line: lineNo}
			continue
		}
		index[key] = len(out)
		out = append(out, Entry{Key: key, Value: value, Line: lineNo})
	}
	return out, nil
}

func hasClosingQuote(s string) bool { return closingQuote(s) >= 0 }

// closingQuote returns the index of the first unescaped " in s, or -1.
func closingQuote(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

func unescape(s string) string {
	r := strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\"`, `"`, `\\`, `\`)
	return r.Replace(s)
}
