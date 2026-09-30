package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindWalksUpToProjectFile(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "envrune.yml"), []byte("version: 1\nproject: x\nenvironments: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Find(nested)
	if err != nil || got != filepath.Join(root, "envrune.yml") {
		t.Fatalf("Find() = %q, %v", got, err)
	}
}
