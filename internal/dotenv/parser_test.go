package dotenv

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAcceptsRestrictedDotenv(t *testing.T) {
	entries, err := Parse([]byte("# comment\nOPENAI_API_KEY=value\nPORT=3000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "OPENAI_API_KEY" || string(entries[0].Value) != "value" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestParseRejectsUnsafeForms(t *testing.T) {
	for _, raw := range []string{"export KEY=value\n", "KEY='value'\n", "KEY=value\nKEY=again\n", "bad-name=value\n", "KEY\n"} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestParseCommonReadsRealWorldFiles(t *testing.T) {
	raw := "# app settings\r\n" +
		"export DATABASE_URL=postgres://u:p@db/app # local db\r\n" +
		"API_KEY = 'sk_live_#not-a-comment'\n" +
		"GREETING=\"hello\\nworld \\\"quoted\\\"\"\n" +
		"PRIVATE_KEY=\"-----BEGIN KEY-----\nabc\n-----END KEY-----\"\n" +
		"RAW=`back ${HOME}`\n" +
		"EMPTY=\n" +
		"PORT=3000\n" +
		"PORT=4000\n"
	entries, err := ParseCommon([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var order []string
	for _, e := range entries {
		got[e.Name] = string(e.Value)
		order = append(order, e.Name)
	}
	want := map[string]string{
		"DATABASE_URL": "postgres://u:p@db/app",
		"API_KEY":      "sk_live_#not-a-comment",
		"GREETING":     "hello\nworld \"quoted\"",
		"PRIVATE_KEY":  "-----BEGIN KEY-----\nabc\n-----END KEY-----",
		"RAW":          "back ${HOME}",
		"EMPTY":        "",
		"PORT":         "4000",
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %v", order)
	}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("%s = %q, want %q", name, got[name], value)
		}
	}
}

func TestParseCommonErrorsNameTheLineNotTheValue(t *testing.T) {
	for raw, line := range map[string]int{
		"A=1\nsecret-value-without-name\n": 2,
		"A=1\nlower=sk_secret\n":           2,
		"A=\"sk_secret_unclosed\n":         1,
		"A='sk_secret' trailing\n":         1,
	} {
		_, err := ParseCommon([]byte(raw))
		var syntax *SyntaxError
		if !errors.As(err, &syntax) || syntax.Line != line || strings.Contains(err.Error(), "secret") {
			t.Fatalf("ParseCommon(%q) = %v", raw, err)
		}
	}
}
