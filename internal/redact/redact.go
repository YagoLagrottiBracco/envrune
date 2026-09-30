// Package redact finds vault values in a stream of bytes and replaces them.
// It backs output masking in `run` and `up` and the searches of `guard`,
// `scan`, and `mcp`. The design is described in docs/redaction.md.
package redact

import (
	"bytes"
	"encoding/base64"
	"io"
	"sort"
	"sync"
	"time"
)

// Mask replaces each value found in output.
const Mask = "****"

// MinLength is the shortest value that is matched. Shorter values, such as
// "true" or "3000", occur in ordinary output too often.
const MinLength = 6

// IdleFlush is how long the writer keeps back bytes that might start a
// value before it writes them anyway.
var IdleFlush = 150 * time.Millisecond

// Secret is a value to look for and the name to report it under, such as
// its reference.
type Secret struct {
	Name  string
	Value []byte
}

// Match is one occurrence of a secret in searched data.
type Match struct {
	Name       string
	Start, End int
}

type pattern struct {
	name  string
	value []byte
}

// Matcher holds the values to look for and their encodings. Call Wipe when
// it is no longer needed.
type Matcher struct {
	patterns []pattern // longest first
	first    [256]bool
	// byPrefix lists, longest first, the patterns that start with each pair
	// of bytes; every pattern has at least MinLength bytes.
	byPrefix map[uint16][]int
	skipped  []string
}

// NewMatcher prepares secrets for searching. It copies the values, so the
// caller may wipe its own copies.
func NewMatcher(secrets []Secret) *Matcher {
	m := &Matcher{}
	for _, secret := range secrets {
		if len(secret.Value) < MinLength {
			m.skipped = append(m.skipped, secret.Name)
			continue
		}
		for _, variant := range variants(secret.Value) {
			if len(variant) < MinLength || m.has(variant) {
				wipe(variant)
				continue
			}
			m.patterns = append(m.patterns, pattern{secret.Name, variant})
			m.first[variant[0]] = true
		}
	}
	sort.SliceStable(m.patterns, func(i, j int) bool { return len(m.patterns[i].value) > len(m.patterns[j].value) })
	m.byPrefix = map[uint16][]int{}
	for i, p := range m.patterns {
		key := prefixKey(p.value)
		m.byPrefix[key] = append(m.byPrefix[key], i)
	}
	sort.Strings(m.skipped)
	return m
}

// Empty reports whether the matcher has nothing to look for.
func (m *Matcher) Empty() bool { return len(m.patterns) == 0 }

// Skipped returns the names of values too short to be matched.
func (m *Matcher) Skipped() []string { return m.skipped }

// Wipe zeroes every value the matcher holds.
func (m *Matcher) Wipe() {
	for _, p := range m.patterns {
		wipe(p.value)
	}
	m.patterns = nil
	m.first = [256]bool{}
	m.byPrefix = nil
}

// Find returns the occurrences in data, leftmost first. Where two values
// overlap, the one that starts first wins, and at the same position the
// longer one.
func (m *Matcher) Find(data []byte) []Match {
	var out []Match
	for i := 0; i < len(data); {
		if m.first[data[i]] {
			if p, ok := m.matchAt(data[i:]); ok {
				out = append(out, Match{Name: p.name, Start: i, End: i + len(p.value)})
				i += len(p.value)
				continue
			}
		}
		i++
	}
	return out
}

// Contains reports whether data holds any value.
func (m *Matcher) Contains(data []byte) bool {
	for i := range data {
		if m.first[data[i]] {
			if _, ok := m.matchAt(data[i:]); ok {
				return true
			}
		}
	}
	return false
}

func (m *Matcher) matchAt(data []byte) (pattern, bool) {
	if len(data) < 2 {
		return pattern{}, false
	}
	for _, i := range m.byPrefix[prefixKey(data)] {
		if p := m.patterns[i]; bytes.HasPrefix(data, p.value) {
			return p, true
		}
	}
	return pattern{}, false
}

func prefixKey(data []byte) uint16 { return uint16(data[0])<<8 | uint16(data[1]) }

// couldStart reports whether data is the beginning of a value that more
// data might complete.
func (m *Matcher) couldStart(data []byte) bool {
	if len(data) == 1 {
		return m.first[data[0]]
	}
	for _, i := range m.byPrefix[prefixKey(data)] {
		if p := m.patterns[i]; len(data) < len(p.value) && bytes.HasPrefix(p.value, data) {
			return true
		}
	}
	return false
}

func (m *Matcher) has(value []byte) bool {
	for _, p := range m.patterns {
		if bytes.Equal(p.value, value) {
			return true
		}
	}
	return false
}

// variants returns the value and the encodings it is likely to appear in.
func variants(value []byte) [][]byte {
	out := [][]byte{append([]byte(nil), value...), percentEncode(value, true), percentEncode(value, false)}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		out = append(out, encoding.AppendEncode(nil, value))
	}
	return out
}

// percentEncode escapes every byte except unreserved characters, with a
// space as "+" in query style and as "%20" otherwise.
func percentEncode(value []byte, query bool) []byte {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(value)*3)
	for _, c := range value {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			out = append(out, c)
		case c == ' ' && query:
			out = append(out, '+')
		default:
			out = append(out, '%', hex[c>>4], hex[c&15])
		}
	}
	return out
}

// Writer masks values in a stream before passing it on. It keeps back only
// the end of the stream that could still start a value, and writes that too
// after IdleFlush without new data. Close writes what is left.
type Writer struct {
	mu      sync.Mutex
	dst     io.Writer
	m       *Matcher
	pending []byte // not yet decided; the first shown bytes were written by an idle flush
	shown   int
	timer   *time.Timer
	closed  bool
}

func NewWriter(dst io.Writer, m *Matcher) *Writer {
	w := &Writer{dst: dst, m: m}
	w.timer = time.AfterFunc(time.Hour, w.idle)
	w.timer.Stop()
	return w
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	w.pending = append(w.pending, p...)
	err := w.drain(false)
	if len(w.pending) > w.shown {
		w.timer.Reset(IdleFlush)
	}
	return len(p), err
}

// Close writes the bytes still kept back and wipes the buffer. It does not
// close the destination.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	w.timer.Stop()
	err := w.drain(true)
	wipe(w.pending)
	w.pending = nil
	return err
}

func (w *Writer) idle() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || len(w.pending) <= w.shown {
		return
	}
	_, _ = w.dst.Write(w.pending[w.shown:])
	w.shown = len(w.pending)
}

// drain writes everything that can be decided. When final is false it stops
// at a tail that could still become a value.
func (w *Writer) drain(final bool) error {
	out := make([]byte, 0, len(w.pending))
	i := 0
	for i < len(w.pending) {
		rest := w.pending[i:]
		if w.m.first[rest[0]] {
			if p, ok := w.m.matchAt(rest); ok {
				out = append(out, Mask...)
				i += len(p.value)
				continue
			}
			if !final && w.m.couldStart(rest) {
				break
			}
		}
		if i >= w.shown {
			out = append(out, rest[0])
		}
		i++
	}
	remaining := append([]byte(nil), w.pending[i:]...)
	wipe(w.pending)
	w.pending = remaining
	w.shown = max(0, w.shown-i)
	if len(out) == 0 {
		return nil
	}
	_, err := w.dst.Write(out)
	wipe(out)
	return err
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// maxLen returns the length of the longest value looked for.
func (m *Matcher) maxLen() int {
	if len(m.patterns) == 0 {
		return 0
	}
	return len(m.patterns[0].value)
}

// scanChunk is how much Scan reads at a time.
const scanChunk = 1 << 20

// Scan reads r to the end and calls found for each value in it, with the
// 1-based line the value starts on. It holds at most one chunk and the
// longest value in memory, so it suits large files such as logs.
func (m *Matcher) Scan(r io.Reader, found func(name string, line int)) error {
	if m.Empty() {
		_, err := io.Copy(io.Discard, r)
		return err
	}
	keep := m.maxLen() - 1
	window := make([]byte, 0, scanChunk+keep)
	defer func() { wipe(window[:cap(window)]) }()
	line := 1 // line number at the start of window
	for {
		n, err := io.ReadFull(r, window[len(window):len(window)+scanChunk])
		window = window[:len(window)+n]
		last := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !last {
			return err
		}
		// A value that starts in the last keep bytes may continue in the
		// next chunk, so it is reported from the next window.
		boundary := len(window)
		if !last {
			boundary = max(0, len(window)-keep)
		}
		counted, lineAt := 0, line
		for _, match := range m.Find(window) {
			if match.Start >= boundary {
				break
			}
			lineAt += bytes.Count(window[counted:match.Start], []byte("\n"))
			counted = match.Start
			found(match.Name, lineAt)
		}
		if last {
			return nil
		}
		line += bytes.Count(window[:boundary], []byte("\n"))
		rest := copy(window, window[boundary:])
		wipe(window[rest:len(window)])
		window = window[:rest]
	}
}
