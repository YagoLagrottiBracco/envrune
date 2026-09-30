package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
)

// inspectResult describes the nearest envrune.yml for editors and other
// tools: names, references, and whether each is stored, never values.
type inspectResult struct {
	Project      string            `json:"project"`
	Path         string            `json:"path"`
	DefaultEnv   string            `json:"default_env,omitempty"`
	Cloud        string            `json:"cloud,omitempty"` // the linked EnvRune Cloud project
	Environments []variablesResult `json:"environments"`
	Commands     []commandInfo     `json:"commands"`
	Up           []string          `json:"up,omitempty"`
	Locked       bool              `json:"locked"` // whether references are stored is unknown
	Problems     []string          `json:"problems,omitempty"`
}

// executeInspect prints inspectResult as JSON. Like the MCP server it never
// prompts: with the vault locked, whether references are stored is left out.
func executeInspect(args []string, stdout, stderr io.Writer) int {
	a, err := parseArgs(args, []string{"dir"}, nil, false)
	if err != nil || len(a.positional) != 0 {
		fmt.Fprintln(stderr, "usage: envrune inspect [--dir <folder>]")
		return 2
	}
	dir := a.options["dir"]
	if dir == "" {
		dir = "."
	}
	s := mcpServer{dir: dir, open: func() (*app.Session, error) {
		return unlocker{getenv: os.Getenv, noPrompt: true, status: NewPresenter(io.Discard, io.Discard, os.Getenv)}.session()
	}}
	path, config, err := s.config()
	if err != nil {
		fmt.Fprintln(stderr, sentence(err.Error()))
		return 1
	}
	out := inspectResult{Project: config.Project, Path: path, Cloud: config.Cloud, Up: config.Up, Problems: config.Validate()}
	if environment, err := app.ChooseEnvironment(config, ""); err == nil {
		out.DefaultEnv = environment
	}
	ctx := context.Background()
	for _, environment := range config.EnvironmentNames() {
		_, variables, err := s.listVariables(ctx, nil, environmentInput{Environment: environment})
		if err != nil {
			fmt.Fprintln(stderr, sentence(err.Error()))
			return 1
		}
		out.Locked = out.Locked || variables.Note != ""
		variables.Note = ""
		out.Environments = append(out.Environments, variables)
	}
	_, commands, _ := s.listCommands(ctx, nil, noInput{})
	out.Commands = commands.Commands
	if out.Environments == nil {
		out.Environments = []variablesResult{}
	}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		return 1
	}
	return 0
}
