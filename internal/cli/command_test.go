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
