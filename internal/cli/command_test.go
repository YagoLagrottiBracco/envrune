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
