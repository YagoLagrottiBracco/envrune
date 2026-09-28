package exporter

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/envrune/envrune/internal/runner"
)

func TestWriteCreatesRestrictedDeterministicDotenv(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.prod")
	if err := Write(path, []runner.Pair{{Name: "B", Value: []byte("two")}, {Name: "A", Value: []byte("one")}}, false); err != nil { t.Fatal(err) }
	raw, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	if string(raw) != "A=one\nB=two\n" { t.Fatalf("content = %q", raw) }
	if runtime.GOOS != "windows" { info, _ := os.Stat(path); if info.Mode().Perm() != 0600 { t.Fatalf("mode = %o", info.Mode().Perm()) } }
}

func TestWriteRefusesOverwriteWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.prod")
	if err := os.WriteFile(path, []byte("OLD=value\n"), 0600); err != nil { t.Fatal(err) }
	if err := Write(path, []runner.Pair{{Name: "NEW", Value: []byte("value")}}, false); !errors.Is(err, ErrExists) { t.Fatalf("error = %v", err) }
}
