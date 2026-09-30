package provider

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

// GitHub stores values as GitHub Actions secrets through the GitHub CLI.
// Secrets cannot be read back, so it only pushes.
type GitHub struct{}

func (GitHub) Name() string    { return "github" }
func (GitHub) Flags() []string { return []string{"repo", "github-env"} }

func (GitHub) Target(_ string, opts Options) string {
	target := "GitHub Actions secrets of the current repository"
	if repo := opts["repo"]; repo != "" {
		target = "GitHub Actions secrets of " + repo
	}
	if env := opts["github-env"]; env != "" {
		target += " (environment " + env + ")"
	}
	return target
}

func (GitHub) Push(ctx context.Context, _ string, values []Value, opts Options) error {
	if _, err := lookPath("gh"); err != nil {
		return fmt.Errorf("the GitHub CLI (gh) is required: install it and run `gh auth login`")
	}
	for _, v := range values {
		args := []string{"secret", "set", v.Name}
		if repo := opts["repo"]; repo != "" {
			args = append(args, "--repo", repo)
		}
		if env := opts["github-env"]; env != "" {
			args = append(args, "--env", env)
		}
		// gh reads the value from standard input.
		cmd := execCommand(ctx, "gh", args...)
		cmd.Stdin = bytes.NewReader(v.Value)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("gh could not store %s: %s", v.Name, strings.TrimSpace(stderr.String()))
		}
	}
	return nil
}
