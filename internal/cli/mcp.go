package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/redact"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpOutputLimit    = 64 << 10
	mcpDefaultTimeout = 120
	mcpMaxTimeout     = 600
)

// Version is the EnvRune version reported to MCP clients; releases set it.
var Version = "dev"

// mcpServer answers an AI agent's tool calls. It never returns a value: the
// design and its limits are in docs/mcp.md.
type mcpServer struct {
	dir       string // where envrune.yml is looked for
	allowArgs bool
	allowAny  bool
	// open unlocks the vault without a prompt, on every call, so that
	// `envrune lock` ends the agent's access at once.
	open func() (*app.Session, error)
}

func executeMCP(args []string, stderr io.Writer) int {
	a, err := parseArgs(args, []string{"project"}, []string{"allow-args", "allow-any-command"}, false)
	if err != nil || len(a.positional) != 0 {
		fmt.Fprintln(stderr, "usage: envrune mcp [--project <folder>] [--allow-args] [--allow-any-command]")
		return 2
	}
	dir := a.options["project"]
	if dir == "" {
		dir = "."
	}
	status := NewPresenter(stderr, stderr, os.Getenv)
	s := mcpServer{
		dir:       dir,
		allowArgs: a.flags["allow-args"],
		allowAny:  a.flags["allow-any-command"],
		open: func() (*app.Session, error) {
			return unlocker{getenv: os.Getenv, noPrompt: true, status: NewPresenter(io.Discard, io.Discard, os.Getenv)}.session()
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.server().Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		status.Error("envrune mcp stopped: " + err.Error())
		return 1
	}
	return 0
}

func (s mcpServer) server() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "envrune", Title: "EnvRune", Version: Version}, &mcp.ServerOptions{
		Instructions: "EnvRune runs this project's commands with secrets from an encrypted vault. " +
			"Use list_commands and run_command instead of reading .env files or running envrune in a shell. " +
			"Secret values never appear in results: any value in the output shows as ****. " +
			"If a tool says the vault is locked, ask the user to run `envrune unlock`.",
	})
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}
	mcp.AddTool(server, &mcp.Tool{Name: "list_environments", Description: "List the environments envrune.yml defines and the default one.", Annotations: readOnly}, s.listEnvironments)
	mcp.AddTool(server, &mcp.Tool{Name: "list_variables", Description: "List the variables of an environment: names, vault references, whether each is stored, and their documentation. Never returns values.", Annotations: readOnly}, s.listVariables)
	mcp.AddTool(server, &mcp.Tool{Name: "list_commands", Description: "List the commands defined under commands: in envrune.yml, which run_command can run.", Annotations: readOnly}, s.listCommands)
	runDescription := "Run a command defined under commands: in envrune.yml, by name, with its secrets injected. Returns the exit code and the output, with every secret value shown as ****."
	if s.allowArgs {
		runDescription += " Extra arguments are appended to the command."
	} else {
		runDescription += " Extra arguments are not accepted."
	}
	mcp.AddTool(server, &mcp.Tool{Name: "run_command", Description: runDescription}, s.runCommand)
	if s.allowAny {
		mcp.AddTool(server, &mcp.Tool{Name: "run_any_command", Description: "Run any command line with the secrets of an environment injected. The output is masked. The user enabled this with --allow-any-command."}, s.runAnyCommand)
	}
	mcp.AddTool(server, &mcp.Tool{Name: "doctor", Description: "Check the vault and envrune.yml: missing or expired secrets, forgotten .env files, and configuration mistakes. Never returns values.", Annotations: readOnly}, s.doctor)
	return server
}

func (s mcpServer) config() (string, project.Config, error) {
	path, err := project.Find(s.dir)
	if err != nil {
		return "", project.Config{}, errors.New("no envrune.yml was found in " + s.dir + " or its parents")
	}
	config, err := project.Load(path)
	if err != nil {
		return "", project.Config{}, errors.New(describe(err, "envrune.yml is invalid."))
	}
	return path, config, nil
}

func (s mcpServer) session() (*app.Session, error) {
	session, err := s.open()
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return nil, errors.New("the vault is locked. Ask the user to run `envrune unlock` in a terminal, then try again")
		}
		return nil, errors.New(describe(err, "the vault could not be opened"))
	}
	return session, nil
}

type noInput struct{}

type environmentsResult struct {
	Environments []string `json:"environments"`
	Default      string   `json:"default,omitempty" jsonschema:"the environment used when none is given"`
}

func (s mcpServer) listEnvironments(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, environmentsResult, error) {
	_, config, err := s.config()
	if err != nil {
		return nil, environmentsResult{}, err
	}
	out := environmentsResult{Environments: config.EnvironmentNames()}
	if chosen, err := app.ChooseEnvironment(config, ""); err == nil {
		out.Default = chosen
	}
	return nil, out, nil
}

type environmentInput struct {
	Environment string `json:"environment,omitempty" jsonschema:"the environment; empty means the default one"`
}

type variableInfo struct {
	Name        string `json:"name"`
	Reference   string `json:"reference,omitempty" jsonschema:"the vault reference the variable is linked to; empty when it is not linked"`
	Stored      *bool  `json:"stored,omitempty" jsonschema:"whether the vault holds the reference; absent while the vault is locked"`
	Description string `json:"description,omitempty"`
	HowToGet    string `json:"how_to_get,omitempty"`
	Type        string `json:"type,omitempty"`
	Format      string `json:"format,omitempty"`
	Required    bool   `json:"required"`
}

type variablesResult struct {
	Environment string         `json:"environment"`
	Variables   []variableInfo `json:"variables"`
	Note        string         `json:"note,omitempty"`
}

func (s mcpServer) listVariables(_ context.Context, _ *mcp.CallToolRequest, in environmentInput) (*mcp.CallToolResult, variablesResult, error) {
	path, config, err := s.config()
	if err != nil {
		return nil, variablesResult{}, err
	}
	environment, err := app.ChooseEnvironment(config, in.Environment)
	if err != nil {
		return nil, variablesResult{}, errors.New(describe(err, "unknown environment"))
	}
	out := variablesResult{Environment: environment}
	session, sessionErr := s.session()
	if sessionErr == nil {
		defer session.Close()
	} else {
		out.Note = "The vault is locked, so whether each reference is stored is unknown."
	}
	mappings := config.Environments[environment]
	names := map[string]bool{}
	for name := range mappings {
		names[name] = true
	}
	for _, v := range config.Variables {
		names[v.Name] = true
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		info := variableInfo{Name: name, Required: true}
		if v, ok := config.Variable(name); ok {
			info.Description, info.HowToGet, info.Type, info.Format, info.Required = v.Description, v.HowToGet, v.Type, v.Format, v.Required
		} else {
			info.Required = false
		}
		if ref, ok := mappings[name]; ok {
			info.Reference = ref.String()
			if sessionErr == nil {
				stored, err := session.Has(path, ref.String())
				if err == nil {
					info.Stored = &stored
				}
			}
		}
		out.Variables = append(out.Variables, info)
	}
	return nil, out, nil
}

type commandInfo struct {
	Name        string `json:"name"`
	Run         string `json:"run"`
	Dir         string `json:"dir,omitempty"`
	Environment string `json:"environment,omitempty"`
	Project     string `json:"project,omitempty"`
}

type commandsResult struct {
	Commands []commandInfo `json:"commands"`
	Up       []string      `json:"up,omitempty" jsonschema:"the commands envrune up starts together"`
}

func (s mcpServer) listCommands(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, commandsResult, error) {
	_, config, err := s.config()
	if err != nil {
		return nil, commandsResult{}, err
	}
	out := commandsResult{Up: config.Up, Commands: []commandInfo{}}
	for name, c := range config.Commands {
		out.Commands = append(out.Commands, commandInfo{name, c.Run, c.Dir, c.Env, c.Project})
	}
	sort.Slice(out.Commands, func(i, j int) bool { return out.Commands[i].Name < out.Commands[j].Name })
	return nil, out, nil
}

type runInput struct {
	Name           string   `json:"name" jsonschema:"the name of a command under commands: in envrune.yml"`
	Environment    string   `json:"environment,omitempty" jsonschema:"the environment; empty means the command's own or the default one"`
	Args           []string `json:"args,omitempty" jsonschema:"extra arguments, accepted only when the user started envrune mcp with --allow-args"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"stop the command after this many seconds; 120 by default, at most 600"`
}

type runAnyInput struct {
	Command        []string `json:"command" jsonschema:"the program and its arguments"`
	Environment    string   `json:"environment,omitempty" jsonschema:"the environment; empty means the default one"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"stop the command after this many seconds; 120 by default, at most 600"`
}

type runResult struct {
	ExitCode  int    `json:"exit_code"`
	Output    string `json:"output" jsonschema:"standard output and error together, with secret values shown as ****"`
	TimedOut  bool   `json:"timed_out,omitempty"`
	Truncated bool   `json:"truncated,omitempty" jsonschema:"true when only the last 64 KiB of output are included"`
	Seconds   int    `json:"seconds"`
}

func (s mcpServer) runCommand(ctx context.Context, _ *mcp.CallToolRequest, in runInput) (*mcp.CallToolResult, runResult, error) {
	path, config, err := s.config()
	if err != nil {
		return nil, runResult{}, err
	}
	command, ok := config.Commands[in.Name]
	if !ok {
		return nil, runResult{}, fmt.Errorf("envrune.yml has no command named %q; call list_commands to see them", in.Name)
	}
	if len(in.Args) > 0 && !s.allowArgs {
		return nil, runResult{}, errors.New("extra arguments are not accepted; the user can allow them by starting envrune mcp with --allow-args")
	}
	words, err := parseShellLine(command.Run)
	if err != nil || len(words) == 0 {
		return nil, runResult{}, fmt.Errorf("commands.%s in envrune.yml has unbalanced quotes", in.Name)
	}
	environment := in.Environment
	if environment == "" {
		environment = command.Env
	}
	secrets, dir := command.Target(path)
	return s.run(ctx, path, secrets, environment, append(words, in.Args...), dir, in.TimeoutSeconds)
}

func (s mcpServer) runAnyCommand(ctx context.Context, _ *mcp.CallToolRequest, in runAnyInput) (*mcp.CallToolResult, runResult, error) {
	path, _, err := s.config()
	if err != nil {
		return nil, runResult{}, err
	}
	if len(in.Command) == 0 {
		return nil, runResult{}, errors.New("command is empty")
	}
	return s.run(ctx, path, path, in.Environment, in.Command, filepath.Dir(path), in.TimeoutSeconds)
}

// run starts words with the environment resolved from secretsPath and
// returns its masked output.
func (s mcpServer) run(ctx context.Context, projectPath, secretsPath, environment string, words []string, dir string, timeout int) (*mcp.CallToolResult, runResult, error) {
	session, err := s.session()
	if err != nil {
		return nil, runResult{}, err
	}
	defer session.Close()
	resolved, err := session.Resolve(secretsPath, environment)
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return nil, runResult{}, errors.New(describe(err, "the command's secrets are unavailable"))
	}
	// Mask every value the user has, not only the ones this command gets.
	all, err := session.Secrets(projectPath)
	if err != nil {
		return nil, runResult{}, errors.New(describe(err, "the vault could not be read"))
	}
	for _, pair := range resolved.Pairs {
		all = append(all, redact.Secret{Name: pair.Name, Value: append([]byte(nil), pair.Value...)})
	}
	matcher := redact.NewMatcher(all)
	for _, secret := range all {
		wipe(secret.Value)
	}
	defer matcher.Wipe()

	if timeout <= 0 {
		timeout = mcpDefaultTimeout
	}
	timeout = min(timeout, mcpMaxTimeout)
	output := &tailBuffer{limit: mcpOutputLimit}
	masked := redact.NewWriter(output, matcher)
	started := time.Now()
	process, err := runner.Start(runner.Spec{
		Command:   words,
		Additions: resolved.Pairs,
		Inherited: os.Environ(),
		Dir:       dir,
		Stdout:    masked,
		Stderr:    masked,
		Group:     true, // the timeout stops everything it starts
	})
	if err != nil {
		_ = masked.Close()
		return nil, runResult{}, errors.New(describe(err, "the command could not start"))
	}
	type exit struct {
		code int
		err  error
	}
	done := make(chan exit, 1)
	go func() {
		code, err := process.Wait()
		done <- exit{code, err}
	}()
	result := runResult{}
	var ended exit
	select {
	case ended = <-done:
	case <-time.After(time.Duration(timeout) * time.Second):
		result.TimedOut = true
		process.Stop()
		ended = <-done
	case <-ctx.Done():
		process.Stop()
		ended = <-done
	}
	process.Stop() // processes the command left behind
	_ = masked.Close()
	result.ExitCode, result.Seconds = ended.code, int(time.Since(started).Seconds())
	result.Output, result.Truncated = output.String()
	return nil, result, nil
}

type findingInfo struct {
	Level   string `json:"level" jsonschema:"ok, warning, or error"`
	Message string `json:"message"`
}

type doctorResult struct {
	Findings []findingInfo `json:"findings"`
}

func (s mcpServer) doctor(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, doctorResult, error) {
	path, _, err := s.config()
	if err != nil {
		return nil, doctorResult{}, err
	}
	findings := app.CheckProject(path)
	if session, err := s.session(); err == nil {
		findings = append(findings, session.CheckSecrets(path, time.Now())...)
		session.Close()
	} else {
		findings = append(findings, app.Finding{Level: app.LevelWarn, Message: err.Error()})
	}
	out := doctorResult{Findings: []findingInfo{}}
	for _, f := range findings {
		level := map[app.Level]string{app.LevelOK: "ok", app.LevelWarn: "warning", app.LevelError: "error"}[f.Level]
		out.Findings = append(out.Findings, findingInfo{level, f.Message})
	}
	return nil, out, nil
}

// tailBuffer keeps the last limit bytes written to it.
type tailBuffer struct {
	mu        sync.Mutex
	limit     int
	buf       []byte
	truncated bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if extra := len(t.buf) - t.limit; extra > 0 {
		t.buf = append(t.buf[:0], t.buf[extra:]...)
		t.truncated = true
	}
	return len(p), nil
}

func (t *tailBuffer) String() (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf), t.truncated
}
