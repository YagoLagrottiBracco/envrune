package redact

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for the writer's idle flush goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func matcher(values ...string) *Matcher {
	secrets := make([]Secret, len(values))
	for i, v := range values {
		secrets[i] = Secret{Name: "ref" + string(rune('a'+i)), Value: []byte(v)}
	}
	return NewMatcher(secrets)
}

func redactChunks(m *Matcher, chunks ...string) string {
	var out syncBuffer
	w := NewWriter(&out, m)
	for _, c := range chunks {
		_, _ = w.Write([]byte(c))
	}
	_ = w.Close()
	return out.String()
}

func TestWriterMasksValueSplitAtEveryPosition(t *testing.T) {
	const secret = "sk-live-4f9a2c"
	text := "token=" + secret + " done\n"
	for cut := 0; cut <= len(text); cut++ {
		for cut2 := cut; cut2 <= len(text); cut2++ {
			got := redactChunks(matcher(secret), text[:cut], text[cut:cut2], text[cut2:])
			if got != "token=****"+" done\n" {
				t.Fatalf("cuts %d,%d: %q", cut, cut2, got)
			}
		}
	}
}

func TestWriterMasksUnicodeAndBytesSplitInsideARune(t *testing.T) {
	const secret = "sênha-çâo-🔑-segura"
	text := "a " + secret + " b"
	for cut := 0; cut <= len(text); cut++ {
		if got := redactChunks(matcher(secret), text[:cut], text[cut:]); got != "a **** b" {
			t.Fatalf("cut %d: %q", cut, got)
		}
	}
}

func TestShortValuesAreNotMatched(t *testing.T) {
	m := matcher("true", "3000", "long-enough")
	if got := redactChunks(m, "port 3000 true long-enough"); got != "port 3000 true ****" {
		t.Fatalf("got %q", got)
	}
	if skipped := m.Skipped(); len(skipped) != 2 {
		t.Fatalf("Skipped() = %v", skipped)
	}
}

func TestEncodedFormsAreMasked(t *testing.T) {
	const secret = "p@ss word/+x"
	m := matcher(secret)
	for _, encoded := range []string{
		"p%40ss+word%2F%2Bx",
		"p%40ss%20word%2F%2Bx",
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
	} {
		if got := redactChunks(m, "x="+encoded+";"); got != "x=****;" {
			t.Fatalf("%s -> %q", encoded, got)
		}
	}
}

func TestLongerValueWinsWhenValuesOverlap(t *testing.T) {
	m := matcher("abcdef", "abcdefghij")
	if got := redactChunks(m, "[abcdefghij] [abcdef]"); got != "[****] [****]" {
		t.Fatalf("got %q", got)
	}
}

func TestWriterDoesNotHoldOrdinaryOutput(t *testing.T) {
	var out syncBuffer
	w := NewWriter(&out, matcher("secret-value"))
	_, _ = w.Write([]byte("hello "))
	if out.String() != "hello " {
		t.Fatalf("ordinary output was held: %q", out.String())
	}
	_, _ = w.Write([]byte("sec"))
	if out.String() != "hello " {
		t.Fatalf("a possible value start was written early: %q", out.String())
	}
	_ = w.Close()
	if out.String() != "hello sec" {
		t.Fatalf("Close() did not flush: %q", out.String())
	}
}

func TestIdleFlushShowsAPromptAndStillMasksTheRest(t *testing.T) {
	old := IdleFlush
	IdleFlush = 20 * time.Millisecond
	defer func() { IdleFlush = old }()
	var out syncBuffer
	w := NewWriter(&out, matcher("secret-value"))
	_, _ = w.Write([]byte("prompt> sec"))
	deadline := time.Now().Add(2 * time.Second)
	for out.String() != "prompt> sec" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if out.String() != "prompt> sec" {
		t.Fatalf("idle flush did not happen: %q", out.String())
	}
	_, _ = w.Write([]byte("ret-value!"))
	_ = w.Close()
	if got := out.String(); got != "prompt> sec****!" || strings.Contains(got, "ret-value") {
		t.Fatalf("got %q", got)
	}
}

func TestFindReportsNamesAndPositions(t *testing.T) {
	m := NewMatcher([]Secret{{"stripe.key", []byte("sk_test_123")}, {"db.url", []byte("postgres://u:p@h/db")}})
	data := []byte("a sk_test_123 b postgres://u:p@h/db")
	got := m.Find(data)
	if len(got) != 2 || got[0].Name != "stripe.key" || string(data[got[0].Start:got[0].End]) != "sk_test_123" || got[1].Name != "db.url" {
		t.Fatalf("Find() = %+v", got)
	}
	if !m.Contains(data) || m.Contains([]byte("nothing here")) {
		t.Fatal("Contains() is wrong")
	}
}

func TestWipeClearsValues(t *testing.T) {
	m := matcher("secret-value")
	values := [][]byte{}
	for _, p := range m.patterns {
		values = append(values, p.value)
	}
	m.Wipe()
	for _, v := range values {
		if bytes.Contains(v, []byte("secret")) {
			t.Fatal("Wipe() left a value in memory")
		}
	}
	if !m.Empty() {
		t.Fatal("matcher is not empty after Wipe()")
	}
}

// BenchmarkWriter streams log-like output past 20 values, several of which
// start with common letters.
func BenchmarkWriter(b *testing.B) {
	var secrets []Secret
	for i := 0; i < 20; i++ {
		secrets = append(secrets, Secret{Name: "ref", Value: []byte("secret-" + strings.Repeat(string(rune('a'+i)), 24))})
	}
	m := NewMatcher(secrets)
	line := []byte("2026-09-30T10:00:00Z INFO server started on port 8000, status ok, request served in 3ms\n")
	chunk := bytes.Repeat(line, 400)
	b.SetBytes(int64(len(chunk)))
	w := NewWriter(io.Discard, m)
	for b.Loop() {
		_, _ = w.Write(chunk)
	}
	_ = w.Close()
}

func TestScanFindsValuesAcrossChunksWithLineNumbers(t *testing.T) {
	m := NewMatcher([]Secret{{Name: "db.url", Value: []byte("postgres://user:pw@db/app")}})
	var text strings.Builder
	for text.Len() < scanChunk-10 {
		text.WriteString("ordinary log line\n")
	}
	lines := strings.Count(text.String(), "\n")
	text.WriteString("connect postgres://user:pw@db/app\n") // straddles the first chunk
	text.WriteString("ok\npostgres://user:pw@db/app\n")
	type hit struct {
		name string
		line int
	}
	var got []hit
	if err := m.Scan(strings.NewReader(text.String()), func(name string, line int) { got = append(got, hit{name, line}) }); err != nil {
		t.Fatal(err)
	}
	want := []hit{{"db.url", lines + 1}, {"db.url", lines + 3}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Scan() = %v, want %v", got, want)
	}
}
