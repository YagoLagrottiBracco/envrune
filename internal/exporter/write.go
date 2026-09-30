// Package exporter writes deliberate plaintext dotenv exports.
package exporter

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

var ErrExists = errors.New("export destination already exists")
var ErrInvalidValue = errors.New("export contains an unsupported value")

func Write(path string, variables []runner.Pair, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	pairs := append([]runner.Pair(nil), variables...)
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Name < pairs[j].Name })
	var out strings.Builder
	for _, pair := range pairs {
		if strings.ContainsAny(string(pair.Value), "\r\n\x00#\\") || len(pair.Value) > 0 && (pair.Value[0] == '\'' || pair.Value[0] == '"') || strings.TrimSpace(string(pair.Value)) != string(pair.Value) {
			return ErrInvalidValue
		}
		out.WriteString(pair.Name)
		out.WriteByte('=')
		out.Write(pair.Value)
		out.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".envrune-export-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.WriteString(out.String()); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if force {
		if err := os.Rename(name, path); err != nil {
			return err
		}
		return syncParent(filepath.Dir(path))
	}
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	if err := os.Remove(name); err != nil {
		return err
	}
	return syncParent(filepath.Dir(path))
}

func syncParent(dir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
