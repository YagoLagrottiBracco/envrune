package runner

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunInjectsOnlyRequestedValuesWithoutEnvFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows host command fixture")
	}
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code, err := Run([]string{"cmd", "/c", "echo %ENVRUNE_SELECTED%"}, []Pair{{Name: "ENVRUNE_SELECTED", Value: []byte("selected")}}, append(os.Environ(), "ENVRUNE_PARENT=kept"), &stdout, &stderr)
	if err != nil || code != 0 {
		t.Fatalf("Run() = %d, %v", code, err)
	}
	if stdout.String() != "selected\r\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Fatal("runner created an env file")
	}
}

func TestRunPropagatesChildExitCode(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows host command fixture")
	}
	code, err := Run([]string{"cmd", "/c", "exit 7"}, nil, os.Environ(), &bytes.Buffer{}, &bytes.Buffer{})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 7 || code != 7 {
		t.Fatalf("Run() = %d, %v", code, err)
	}
}

func TestRunReportsMissingCommandByName(t *testing.T) {
	code, err := Run([]string{"envrune-no-such-command"}, nil, os.Environ(), &bytes.Buffer{}, &bytes.Buffer{})
	var missing *CommandNotFoundError
	if !errors.As(err, &missing) || missing.Name != "envrune-no-such-command" || code != 127 {
		t.Fatalf("Run() = %d, %v", code, err)
	}
}

func TestRunResolvesBareCommandFromPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows host command fixture")
	}
	var stdout bytes.Buffer
	code, err := Run([]string{"cmd", "/c", "echo ok"}, nil, os.Environ(), &stdout, &bytes.Buffer{})
	if err != nil || code != 0 || stdout.String() != "ok\r\n" {
		t.Fatalf("Run() = %d, %v, %q", code, err, stdout.String())
	}
}

func TestStopEndsAGroupedChild(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows host command fixture")
	}
	p, err := Start(Spec{Command: []string{"cmd", "/c", "ping -n 30 127.0.0.1 >nul"}, Inherited: os.Environ(), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Group: true})
	if err != nil {
		t.Fatal(err)
	}
	p.Stop()
	if code, err := p.Wait(); err == nil || code == 0 {
		t.Fatalf("Wait() = %d, %v", code, err)
	}
}
