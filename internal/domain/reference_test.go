package domain

import "testing"

func TestParseReferenceAcceptsDotSeparatedLowercaseSegments(t *testing.T) {
	got, err := ParseReference("openai.personal")
	if err != nil || got.String() != "openai.personal" {
		t.Fatalf("ParseReference() = %q, %v", got.String(), err)
	}
}

func TestParseReferenceRejectsUnsafeForms(t *testing.T) {
	for _, raw := range []string{"", "OpenAI.personal", "openai..personal", "openai/personal", "-openai", "openai.", "openai_1"} {
		if _, err := ParseReference(raw); err == nil {
			t.Errorf("ParseReference(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestParseReferenceRejectsOverlongInput(t *testing.T) {
	raw := "a"
	for len(raw) <= 128 {
		raw += "a"
	}
	if _, err := ParseReference(raw); err == nil {
		t.Fatal("ParseReference() unexpectedly accepted overlong input")
	}
}
