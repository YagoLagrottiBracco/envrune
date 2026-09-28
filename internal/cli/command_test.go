package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestSetRejectsValueAsSecondPositionalArgument(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute([]string{"set", "openai.personal", "enrune-test-secret-DO-NOT-LEAK"}, &out, &errOut)
	if code == 0 {
		t.Fatal("expected failure")
	}
	if strings.Contains(out.String()+errOut.String(), "enrune-test-secret-DO-NOT-LEAK") {
		t.Fatal("secret leaked")
	}
}

func TestLinkRejectsMissingEnvironmentWithoutEchoingReference(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute([]string{"link", "OPENAI_API_KEY", "openai.personal"}, &out, &errOut)
	if code == 0 {
		t.Fatal("expected failure")
	}
	if strings.Contains(out.String()+errOut.String(), "openai.personal") {
		t.Fatal("reference should not be echoed in syntax errors")
	}
}

func TestHelpFlagShowsUsageWithoutPromptingForPassword(t *testing.T) {
	var out, errOut bytes.Buffer

	code := Execute([]string{"--help"}, &out, &errOut)

	if code != 0 {
		t.Fatalf("expected success, got %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Usage: envrune") {
		t.Fatalf("expected usage on stdout, got %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", errOut.String())
	}
}
