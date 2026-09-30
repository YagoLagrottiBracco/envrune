package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunInjectsOnlyRequestedValuesWithoutEnvFile(t *testing.T) {
	if runtime.GOOS != "windows" { t.Skip("Windows host command fixture") }
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code, err := Run([]string{"cmd", "/c", "echo %ENVRUNE_SELECTED%"}, []Pair{{Name: "ENVRUNE_SELECTED", Value: []byte("selected")}}, append(os.Environ(), "ENVRUNE_PARENT=kept"), &stdout, &stderr)
	if err != nil || code != 0 { t.Fatalf("Run() = %d, %v", code, err) }
	if stdout.String() != "selected\r\n" { t.Fatalf("stdout = %q", stdout.String()) }
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) { t.Fatal("runner created an env file") }
}

func TestRunPropagatesChildExitCode(t *testing.T) {
	if runtime.GOOS != "windows" { t.Skip("Windows host command fixture") }
	code, err := Run([]string{"cmd", "/c", "exit 7"}, nil, os.Environ(), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || code != 7 { t.Fatalf("Run() = %d, %v", code, err) }
}
