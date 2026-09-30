package project

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrNotFound = errors.New("envrune project not found")

func Find(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", ErrNotFound
	}
	for {
		candidate := filepath.Join(dir, "envrune.yml")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrNotFound
		}
		dir = parent
	}
}
