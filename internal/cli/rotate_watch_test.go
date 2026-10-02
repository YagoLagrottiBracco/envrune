package cli

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// holdWhile prints the variable and keeps running only while it holds the
// first value, so a test ends once the command runs with the second one.
func holdWhile(first string) []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/c", "echo got %API_KEY%& if %API_KEY%==" + first + " ping -n 30 127.0.0.1 >nul"}
	}
	return []string{"sh", "-c", `echo got $API_KEY; if [ "$API_KEY" = ` + first + ` ]; then sleep 30; fi`}
}

func watchFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, baseConfig)
	if err := f.session.Set("demo.api-key", []byte("first-value-123")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "development", "API_KEY", "demo.api-key"); err != nil {
		t.Fatal(err)
	}
	previous := rotationPollInterval
	rotationPollInterval = 50 * time.Millisecond
	t.Cleanup(func() { rotationPollInterval = previous })
	return f
}

func TestRunRestartsOnRotateWithTheNewValue(t *testing.T) {
	f := watchFixture(t)
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = f.session.Set("demo.api-key", []byte("second-value-456"))
	}()
	started := time.Now()
	code := f.run(append([]string{"run", "--no-redact", "--restart-on-rotate", "--"}, holdWhile("first-value-123")...)...)
	out := f.output()
	if code != 0 || !strings.Contains(out, "got first-value-123") || !strings.Contains(out, "got second-value-456") {
		t.Fatalf("run = %d after %s:\n%s", code, time.Since(started), out)
	}
	if !strings.Contains(out, "New values arrived for API_KEY: restarting") {
		t.Fatalf("the restart was not announced:\n%s", out)
	}
	if time.Since(started) > 20*time.Second {
		t.Fatalf("the first command was not stopped; the run took %s", time.Since(started))
	}
}

func TestRunWarnsAboutNewValuesWithoutRestarting(t *testing.T) {
	f := watchFixture(t)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = f.session.Set("demo.api-key", []byte("second-value-456"))
	}()
	command := []string{"sh", "-c", "echo got $API_KEY; sleep 1"}
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "echo got %API_KEY%& ping -n 2 127.0.0.1 >nul"}
	}
	code := f.run(append([]string{"run", "--"}, command...)...)
	out := f.output()
	if code != 0 || strings.Contains(out, "second-value-456") || strings.Count(out, "got ") != 1 {
		t.Fatalf("run = %d, and the command was restarted or showed a value:\n%s", code, out)
	}
	if !strings.Contains(out, "New values arrived for API_KEY") || !strings.Contains(out, "--restart-on-rotate") {
		t.Fatalf("no warning about the new value:\n%s", out)
	}
}
