package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestUIValidatesPortAndRejectsExtraArgumentsBeforeReadingPassword(t *testing.T) {
	for _, args := range [][]string{{"--port", "-1"}, {"--port", "65536"}, {"--port"}, {"--port", "abc"}, {"--host", "0.0.0.0"}, {"SENTINEL"}, {"--port", "0", "--port", "1"}} {
		var out, errOut bytes.Buffer
		code := Execute(append([]string{"ui"}, args...), &out, &errOut)
		if code != 2 || !strings.Contains(errOut.String(), "usage: envrune ui") {
			t.Fatalf("unexpected syntax handling for %v: %d %s", args, code, errOut.String())
		}
		if strings.Contains(out.String()+errOut.String(), "SENTINEL") {
			t.Fatal("argument reflected")
		}
	}
}

func TestUIArgumentsAllowEphemeralOrExplicitPortAndNoBrowser(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		port    int
		browser bool
	}{{nil, 0, true}, {[]string{"--port", "43210"}, 43210, true}, {[]string{"--no-browser", "--port", "0"}, 0, false}} {
		port, browser, err := uiArguments(tc.args)
		if err != nil || port != tc.port || browser != tc.browser {
			t.Fatalf("unexpected UI options: %d %t %v", port, browser, err)
		}
	}
}
