//go:build integration

package integration

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Node and Python packages load variables through the real envrune
// binary and vault. Each test is skipped where its runtime is missing.

func TestPythonPackageLoadsFromTheVault(t *testing.T) {
	python := workingPython()
	if python == "" {
		t.Skip("Python is not installed")
	}
	src, _ := filepath.Abs(filepath.Join("..", "..", "packages", "python", "src"))
	h := newHarness(t)
	h.set("demo.api-key", "sk-live-python-value")
	dir := h.project("app", devConfig)
	script := "import sys; sys.path.insert(0, sys.argv[1]); import os, envrune; envrune.load(); print('loaded', os.environ['API_KEY'][:7])"
	cmd := exec.Command(python, "-c", script, src)
	cmd.Dir, cmd.Env = dir, h.environ()
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "loaded sk-live") {
		t.Fatalf("python: %v\n%s", err, out)
	}

	locked := exec.Command(python, "-c", "import sys; sys.path.insert(0, sys.argv[1]); import envrune\ntry:\n  envrune.load()\nexcept envrune.EnvruneError as e:\n  print('error:', e)", src)
	locked.Dir = dir
	for _, entry := range h.environ() {
		if !strings.HasPrefix(entry, "ENVRUNE_PASSWORD=") {
			locked.Env = append(locked.Env, entry)
		}
	}
	out, _ = locked.CombinedOutput()
	if !strings.Contains(string(out), "error: The vault is locked") {
		t.Fatalf("python with a locked vault:\n%s", out)
	}
}

// workingPython finds a Python 3 that runs. On Windows, python3 can be a
// Microsoft Store shortcut that only opens the store.
func workingPython() string {
	for _, name := range []string{"python3", "python"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if out, err := exec.Command(path, "-c", "import sys; print(sys.version_info[0])").Output(); err == nil && strings.TrimSpace(string(out)) == "3" {
			return path
		}
	}
	return ""
}

func TestNodePackageLoadsFromTheVault(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	pkg, _ := filepath.Abs(filepath.Join("..", "..", "packages", "node", "config.js"))
	h := newHarness(t)
	h.set("demo.api-key", "sk-live-node-value")
	dir := h.project("app", devConfig)
	script := "await import(process.argv[1]); console.log('loaded', process.env.API_KEY.slice(0, 7))"
	url := filepath.ToSlash(pkg)
	if !strings.HasPrefix(url, "/") {
		url = "/" + url // C:/... on Windows
	}
	cmd := exec.Command(node, "--input-type=module", "-e", script, "file://"+url)
	cmd.Dir, cmd.Env = dir, h.environ()
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "loaded sk-live") {
		t.Fatalf("node: %v\n%s", err, out)
	}
}
