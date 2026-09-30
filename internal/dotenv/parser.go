// Package dotenv parses dotenv files: Parse reads the deliberately
// restricted format of `envrune import`, and ParseCommon reads the syntax
// dotenv libraries accept, for `envrune migrate`.
package dotenv

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	ErrInvalid   = errors.New("invalid dotenv input")
	ErrDuplicate = errors.New("duplicate dotenv variable")
)

// Entry is one parsed dotenv assignment. Value is owned by the caller.
type Entry struct {
	Name  string
	Value []byte
}

// Parse accepts only comments, blank lines, and unquoted POSIX NAME=value assignments.
func Parse(raw []byte) ([]Entry, error) {
	entries := make([]Entry, 0)
	seen := make(map[string]struct{})
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		equals := bytes.IndexByte(line, '=')
		if equals < 1 || !validName(line[:equals]) {
			return nil, ErrInvalid
		}
		value := line[equals+1:]
		if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
			return nil, ErrInvalid
		}
		name := string(line[:equals])
		if _, exists := seen[name]; exists {
			return nil, ErrDuplicate
		}
		seen[name] = struct{}{}
		entries = append(entries, Entry{Name: name, Value: append([]byte(nil), value...)})
	}
	return entries, nil
}

func validName(name []byte) bool {
	if len(name) == 0 || !((name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_') {
		return false
	}
	for _, character := range name[1:] {
		if !((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_') {
			return false
		}
	}
	return true
}

// SyntaxError reports a line ParseCommon could not read. It never includes
// the line's content, which may hold a value.
type SyntaxError struct {
	Line   int
	Reason string
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Reason) }

func (e *SyntaxError) Is(target error) bool { return target == ErrInvalid }

// ParseCommon reads the dotenv syntax that the dotenv libraries for Node and
// Python accept, for migrating existing files: an optional `export` prefix,
// spaces around `=`, unquoted values with ` #` comments, 'single' and
// `backtick` quotes taken literally, and "double" quotes with \n, \r, \t,
// \", and \ escapes. Quoted values may span lines. A later assignment of
// the same name wins, as in those libraries. ${VAR} is kept as written.
func ParseCommon(raw []byte) ([]Entry, error) {
	var entries []Entry
	index := map[string]int{}
	lines := bytes.Split(raw, []byte{'\n'})
	for i := 0; i < len(lines); i++ {
		number := i + 1
		line := bytes.TrimSpace(bytes.TrimSuffix(lines[i], []byte{'\r'}))
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if rest, ok := bytes.CutPrefix(line, []byte("export ")); ok {
			line = bytes.TrimLeft(rest, " \t")
		}
		equals := bytes.IndexByte(line, '=')
		if equals < 1 {
			return nil, &SyntaxError{number, "expected NAME=value"}
		}
		name := bytes.TrimRight(line[:equals], " \t")
		if !validName(name) {
			return nil, &SyntaxError{number, "the name must use uppercase letters, digits, and _"}
		}
		value := bytes.TrimLeft(line[equals+1:], " \t")
		var parsed []byte
		if len(value) > 0 && (value[0] == '"' || value[0] == '\'' || value[0] == '`') {
			quote := value[0]
			body := append([]byte(nil), value[1:]...)
			end := closingQuote(body, quote)
			for end < 0 && i+1 < len(lines) {
				i++
				body = append(append(body, '\n'), bytes.TrimSuffix(lines[i], []byte{'\r'})...)
				end = closingQuote(body, quote)
			}
			if end < 0 {
				wipe(body)
				return nil, &SyntaxError{number, "a quoted value is not closed"}
			}
			if after := bytes.TrimSpace(body[end+1:]); len(after) > 0 && after[0] != '#' {
				wipe(body)
				return nil, &SyntaxError{number, "unexpected text after a quoted value"}
			}
			parsed = body[:end]
			if quote == '"' {
				parsed = unescape(parsed)
			}
		} else {
			if comment := bytes.Index(value, []byte(" #")); comment >= 0 {
				value = value[:comment]
			} else if comment := bytes.Index(value, []byte("\t#")); comment >= 0 {
				value = value[:comment]
			}
			parsed = append([]byte(nil), bytes.TrimRight(value, " \t")...)
		}
		entry := Entry{Name: string(name), Value: parsed}
		if at, ok := index[entry.Name]; ok {
			wipe(entries[at].Value)
			entries[at] = entry
			continue
		}
		index[entry.Name] = len(entries)
		entries = append(entries, entry)
	}
	return entries, nil
}

// closingQuote finds the quote that ends body, skipping \" inside double
// quotes.
func closingQuote(body []byte, quote byte) int {
	for i := 0; i < len(body); i++ {
		if quote == '"' && body[i] == '\\' {
			i++
			continue
		}
		if body[i] == quote {
			return i
		}
	}
	return -1
}

func unescape(value []byte) []byte {
	out := value[:0]
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 == len(value) {
			out = append(out, value[i])
			continue
		}
		i++
		switch value[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '"', '\\':
			out = append(out, value[i])
		default:
			out = append(out, '\\', value[i])
		}
	}
	return out
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
