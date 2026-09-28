// Package dotenv parses the deliberately restricted import interchange format.
package dotenv

import (
	"bytes"
	"errors"
)

var (
	ErrInvalid = errors.New("invalid dotenv input")
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
