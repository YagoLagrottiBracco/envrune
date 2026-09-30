package dotenv

import "testing"

func TestParseAcceptsRestrictedDotenv(t *testing.T) {
	entries, err := Parse([]byte("# comment\nOPENAI_API_KEY=value\nPORT=3000\n"))
	if err != nil { t.Fatal(err) }
	if len(entries) != 2 || entries[0].Name != "OPENAI_API_KEY" || string(entries[0].Value) != "value" { t.Fatalf("unexpected entries: %#v", entries) }
}

func TestParseRejectsUnsafeForms(t *testing.T) {
	for _, raw := range []string{"export KEY=value\n", "KEY='value'\n", "KEY=value\nKEY=again\n", "bad-name=value\n", "KEY\n"} { if _, err := Parse([]byte(raw)); err == nil { t.Fatalf("Parse(%q) unexpectedly succeeded", raw) } }
}
