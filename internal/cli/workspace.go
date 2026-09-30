package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/agent"
	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/clipboard"
	"github.com/YagoLagrottiBracco/envrune/internal/dotenv"
	"github.com/YagoLagrottiBracco/envrune/internal/exporter"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

// Workspace runs the commands that need an unlocked vault. The one-shot CLI
// and the interactive shell share it, so every command works in both.
type Workspace struct {
	Session     *app.Session
	Stdout      io.Writer
	Stderr      io.Writer
	ReadSecret  func(string) ([]byte, error)
	ReadChoice  func(string) (string, error)
	FindProject func(string) (string, error)
	Environment func() []string
	StartUI     func(*app.Session, []string, io.Writer, io.Writer) int
}

type handler func(Workspace, []string) int

var sessionCommands map[string]handler

func init() {
	sessionCommands = map[string]handler{
		"set":      Workspace.set,
		"generate": Workspace.generate,
		"list":     Workspace.list,
		"info":     Workspace.info,
		"meta":     Workspace.meta,
		"remove":   Workspace.remove,
		"copy":     Workspace.copyValue,
		"link":     Workspace.link,
		"usage":    Workspace.usage,
		"import":   Workspace.importFile,
		"run":      Workspace.run,
		"export":   Workspace.export,
		"up":       Workspace.up,
		"rotate":   Workspace.rotate,
		"rollback": Workspace.rollback,
		"history":  Workspace.history,
		"doctor":   Workspace.doctor,
		"passwd":   Workspace.passwd,
		"recovery": Workspace.recovery,
		"team":     Workspace.team,
		"push":     Workspace.push,
		"env":      Workspace.env,
		"unlock":   Workspace.unlock,
		"ui":       Workspace.ui,
	}
}

// isSessionCommand reports whether name is a built-in command that needs
// the vault.
func isSessionCommand(name string) bool {
	_, ok := sessionCommands[name]
	return ok
}

func (w Workspace) status() Presenter { return NewPresenter(w.Stdout, w.Stderr, os.Getenv) }

// Execute runs one command line. Built-in commands come first, then the
// commands defined in envrune.yml.
func (w Workspace) Execute(argv []string) int {
	if len(argv) == 0 {
		return 0
	}
	if run, ok := sessionCommands[argv[0]]; ok {
		return run(w, argv[1:])
	}
	if projectPath, err := w.findProject(); err == nil {
		if config, err := project.Load(projectPath); err == nil {
			if _, ok := config.Commands[argv[0]]; ok {
				return w.runNamed(projectPath, config, argv[0], argv[1:])
			}
		}
	}
	w.status().Error("Unknown command. Run `help` to see the commands.")
	return 2
}

func (w Workspace) usageError(usage string) int {
	w.status().Error("Usage: " + usage)
	return 2
}

func (w Workspace) fail(err error, fallback string) int {
	w.status().Error(describe(err, fallback))
	return 1
}

func (w Workspace) findProject() (string, error) {
	find := w.FindProject
	if find == nil {
		find = project.Find
	}
	return find(".")
}

func (w Workspace) environ() []string {
	if w.Environment == nil {
		return os.Environ()
	}
	return w.Environment()
}

func (w Workspace) confirm() bool {
	if w.ReadSecret == nil {
		return false
	}
	value, err := w.ReadSecret("Type YES to confirm")
	if err != nil {
		return false
	}
	defer wipe(value)
	return string(value) == "YES"
}

// projectPathOrEmpty returns envrune.yml when there is one; team references
// need it, vault references do not.
func (w Workspace) projectPathOrEmpty() string {
	path, err := w.findProject()
	if err != nil {
		return ""
	}
	return path
}

func (w Workspace) set(argv []string) int {
	a, err := parseArgs(argv, nil, nil, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError("set <reference>")
	}
	ref := a.positional[0]
	value, err := readConfirmedValue(w.ReadSecret, "Secret value")
	if err != nil {
		return w.fail(err, "Secure interactive input is required.")
	}
	defer wipe(value)
	if strings.HasPrefix(ref, team.Prefix) {
		err = w.teamSetValue(ref, value)
	} else {
		err = w.Session.Set(ref, value)
	}
	if err != nil {
		return w.fail(err, "Secret could not be stored.")
	}
	w.status().Success(fmt.Sprintf("Secret stored: %s", ref))
	return 0
}

func (w Workspace) generate(argv []string) int {
	a, err := parseArgs(argv, []string{"length"}, nil, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError("generate <reference> [--length <n>]")
	}
	length := 32
	if raw, ok := a.options["length"]; ok {
		if length, err = strconv.Atoi(raw); err != nil {
			return w.usageError("generate <reference> [--length <n>]")
		}
	}
	if err := w.Session.Generate(a.positional[0], length); err != nil {
		return w.fail(err, "Secret generation failed.")
	}
	w.status().Success(fmt.Sprintf("Generated and stored a %d-character secret: %s", length, a.positional[0]))
	return 0
}

func (w Workspace) list(argv []string) int {
	a, err := parseArgs(argv, nil, []string{"long"}, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError("list [--long]")
	}
	if !a.flags["long"] {
		refs, err := w.Session.List()
		if err != nil {
			return w.fail(err, "Secret references are unavailable.")
		}
		for _, ref := range refs {
			fmt.Fprintln(w.Stdout, ref)
		}
		w.status().Success(fmt.Sprintf("%d secret references listed.", len(refs)))
		return 0
	}
	infos, err := w.Session.Infos()
	if err != nil {
		return w.fail(err, "Secret references are unavailable.")
	}
	table := tabwriter.NewWriter(w.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "REFERENCE\tUPDATED\tOWNER\tEXPIRES\tDESCRIPTION")
	for _, info := range infos {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", info.Reference, day(info.UpdatedAt), dash(info.Owner), dash(info.Expires), info.Description)
	}
	_ = table.Flush()
	return 0
}

func day(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Local().Format(time.DateOnly)
}

func dash(text string) string {
	if text == "" {
		return "-"
	}
	return text
}

func (w Workspace) info(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("info <reference>")
	}
	info, err := w.Session.Info(argv[0])
	if err != nil {
		return w.fail(err, "Secret information is unavailable.")
	}
	fmt.Fprintf(w.Stdout, "Reference:   %s\n", info.Reference)
	fmt.Fprintf(w.Stdout, "Description: %s\n", dash(info.Description))
	fmt.Fprintf(w.Stdout, "Owner:       %s\n", dash(info.Owner))
	fmt.Fprintf(w.Stdout, "Expires:     %s\n", dash(info.Expires))
	fmt.Fprintf(w.Stdout, "Created:     %s\n", day(info.CreatedAt))
	fmt.Fprintf(w.Stdout, "Updated:     %s\n", day(info.UpdatedAt))
	fmt.Fprintf(w.Stdout, "Earlier values kept: %d\n", len(info.Previous))
	usages, err := w.Session.Usage(argv[0])
	if err == nil {
		for _, usage := range usages {
			fmt.Fprintf(w.Stdout, "Used by:     %s %s %s\n", usage.ProjectPath, usage.Environment, usage.Variable)
		}
	}
	return 0
}

func (w Workspace) meta(argv []string) int {
	const usage = "meta <reference> [--description <text>] [--owner <name>] [--expires YYYY-MM-DD|none]"
	a, err := parseArgs(argv, []string{"description", "owner", "expires"}, nil, false)
	if err != nil || len(a.positional) != 1 || len(a.options) == 0 {
		return w.usageError(usage)
	}
	var change vault.MetaChange
	if value, ok := a.options["description"]; ok {
		change.Description = &value
	}
	if value, ok := a.options["owner"]; ok {
		change.Owner = &value
	}
	if value, ok := a.options["expires"]; ok {
		if value == "none" {
			value = ""
		} else if _, err := time.Parse(time.DateOnly, value); err != nil {
			w.status().Error("Use --expires YYYY-MM-DD, such as 2026-12-31, or none.")
			return 2
		}
		change.Expires = &value
	}
	if err := w.Session.SetMeta(a.positional[0], change); err != nil {
		return w.fail(err, "Secret metadata could not be stored.")
	}
	w.status().Success(fmt.Sprintf("Metadata updated: %s", a.positional[0]))
	return 0
}

func (w Workspace) remove(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("remove <reference>")
	}
	if usages, err := w.Session.Usage(argv[0]); err == nil && len(usages) > 0 {
		for _, usage := range usages {
			fmt.Fprintf(w.Stdout, "%s %s %s\n", usage.ProjectPath, usage.Environment, usage.Variable)
		}
		w.status().Warn("These bindings will stop resolving.")
	}
	w.status().Warn(fmt.Sprintf("This deletes %s and its earlier values.", argv[0]))
	if !w.confirm() {
		w.status().Error("Confirmation is required.")
		return 1
	}
	if err := w.Session.Remove(argv[0]); err != nil {
		return w.fail(err, "Secret could not be removed.")
	}
	w.status().Success(fmt.Sprintf("Secret removed: %s", argv[0]))
	return 0
}

func (w Workspace) copyValue(argv []string) int {
	a, err := parseArgs(argv, []string{"clear-after"}, nil, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError("copy <reference> [--clear-after 30s]")
	}
	delay := 30 * time.Second
	if raw, ok := a.options["clear-after"]; ok {
		if delay, err = time.ParseDuration(raw); err != nil || delay <= 0 {
			return w.usageError("copy <reference> [--clear-after 30s]")
		}
	}
	value, err := w.Session.Reveal(w.projectPathOrEmpty(), a.positional[0])
	if err != nil {
		return w.fail(err, "Secret is unavailable.")
	}
	defer wipe(value)
	if err := clipboard.Copy(value, delay); err != nil {
		return w.fail(err, "The clipboard is unavailable.")
	}
	w.status().Success(fmt.Sprintf("Copied %s to the clipboard. It will be cleared in %s.", a.positional[0], delay))
	return 0
}

func (w Workspace) link(argv []string) int {
	const usage = "link <VAR> <reference> [--env <environment>]"
	a, err := parseArgs(argv, []string{"env"}, nil, false)
	if err != nil || len(a.positional) != 2 {
		return w.usageError(usage)
	}
	variable, ref := a.positional[0], a.positional[1]
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	environment := a.options["env"]
	if environment == "" {
		config, err := project.Load(projectPath)
		if err != nil {
			return w.fail(err, "The project configuration is invalid.")
		}
		if environment, err = app.ChooseEnvironment(config, ""); err != nil {
			return w.fail(err, "Choose an environment with --env.")
		}
	}
	if err := w.Session.Link(projectPath, environment, variable, ref); err != nil {
		return w.fail(err, "The project link could not be created.")
	}
	w.status().Success(fmt.Sprintf("Linked %s to %s for environment %s.", variable, ref, environment))
	if exists, err := w.Session.Has(projectPath, ref); err == nil && !exists {
		return w.offerValue(ref)
	}
	return 0
}

// offerValue asks for the value of a reference that does not exist yet, so
// link and set are one step.
func (w Workspace) offerValue(ref string) int {
	status := w.status()
	if w.ReadChoice == nil {
		status.Warn(fmt.Sprintf("%s does not exist yet. Store it with `set %s`.", ref, ref))
		return 0
	}
	choice, err := w.ReadChoice(fmt.Sprintf("%s does not exist yet. Enter its value now? [y/N]", ref))
	if err != nil || !acceptsSetup(choice) {
		status.Info(fmt.Sprintf("Store it later with `set %s`.", ref))
		return 0
	}
	return w.set([]string{ref})
}

func (w Workspace) usage(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("usage <reference>")
	}
	usages, err := w.Session.Usage(argv[0])
	if err != nil {
		return w.fail(err, "Secret usage is unavailable.")
	}
	for _, usage := range usages {
		fmt.Fprintf(w.Stdout, "%s %s %s\n", usage.ProjectPath, usage.Environment, usage.Variable)
	}
	w.status().Success("Secret usage listed.")
	return 0
}

func (w Workspace) importFile(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("import <file.env>")
	}
	raw, err := os.ReadFile(argv[0])
	if err != nil {
		return w.fail(err, "The import file is unavailable.")
	}
	entries, err := dotenv.Parse(raw)
	wipe(raw)
	if err != nil {
		return w.fail(err, "The dotenv input is invalid.")
	}
	for _, entry := range entries {
		fmt.Fprintln(w.Stdout, entry.Name)
	}
	if !w.confirm() {
		w.status().Error("Confirmation is required.")
		return 1
	}
	count, err := w.Session.Import(entries)
	if err != nil {
		return w.fail(err, "Secrets could not be imported.")
	}
	w.status().Success(fmt.Sprintf("%d secrets imported under import.var-*. Link them with `link <VAR> <reference>`.", count))
	return 0
}

// resolve finds envrune.yml and resolves one environment, or the default.
func (w Workspace) resolve(environment string) (string, app.Resolved, error) {
	projectPath, err := w.findProject()
	if err != nil {
		return "", app.Resolved{}, err
	}
	resolved, err := w.Session.Resolve(projectPath, environment)
	return projectPath, resolved, err
}

func (w Workspace) run(argv []string) int {
	const usage = "run [--env <environment>] [--] <command> [args...]"
	a, err := parseArgs(argv, []string{"env"}, nil, true)
	if err != nil || len(a.rest) == 0 {
		return w.usageError(usage)
	}
	_, resolved, err := w.resolve(a.options["env"])
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	status := w.status()
	status.Info(fmt.Sprintf("Starting %s with %d variables from %s.", a.rest[0], len(resolved.Pairs), resolved.Environment))
	code, runErr := runner.Run(a.rest, resolved.Pairs, w.environ(), w.Stdout, w.Stderr)
	if runErr != nil {
		status.Error(describe(runErr, "The command could not be run."))
	}
	return code
}

// runNamed runs a command defined under commands: in envrune.yml.
func (w Workspace) runNamed(projectPath string, config project.Config, name string, argv []string) int {
	a, err := parseArgs(argv, []string{"env"}, nil, true)
	if err != nil {
		return w.usageError(name + " [--env <environment>] [args...]")
	}
	command := config.Commands[name]
	words, err := parseShellLine(command.Run)
	if err != nil || len(words) == 0 {
		w.status().Error(fmt.Sprintf("commands.%s in envrune.yml has unbalanced quotes.", name))
		return 2
	}
	words = append(words, a.rest...)
	environment := a.options["env"]
	if environment == "" {
		environment = command.Env
	}
	resolved, err := w.Session.Resolve(projectPath, environment)
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	status := w.status()
	status.Info(fmt.Sprintf("Running %s with %d variables from %s.", name, len(resolved.Pairs), resolved.Environment))
	process, err := runner.Start(runner.Spec{
		Command:   words,
		Additions: resolved.Pairs,
		Inherited: w.environ(),
		Dir:       filepath.Join(filepath.Dir(projectPath), command.Dir),
		Stdin:     os.Stdin,
		Stdout:    w.Stdout,
		Stderr:    w.Stderr,
	})
	if err != nil {
		return w.fail(err, "The command could not be run.")
	}
	code, err := process.Wait()
	if err != nil {
		status.Error(describe(err, "The command failed."))
	}
	return code
}

func (w Workspace) export(argv []string) int {
	const usage = "export [--env <environment>] [--output <path>] [--force]"
	a, err := parseArgs(argv, []string{"env", "output"}, []string{"force"}, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError(usage)
	}
	_, resolved, err := w.resolve(a.options["env"])
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	output, err := exportPath(a.options["output"], resolved.Environment)
	if err != nil {
		w.status().Error("Export arguments are invalid.")
		return 2
	}
	for _, pair := range resolved.Pairs {
		fmt.Fprintln(w.Stdout, pair.Name)
	}
	status := w.status()
	status.Warn("Export writes plaintext secrets. Delete the file after use.")
	if !w.confirm() {
		status.Error("Confirmation is required.")
		return 1
	}
	if insideGit(filepath.Dir(output)) && !w.confirm() {
		status.Error("Additional confirmation is required for a Git directory.")
		return 1
	}
	if err := exporter.Write(output, resolved.Pairs, a.flags["force"]); err != nil {
		return w.fail(err, "Plaintext export could not be created.")
	}
	status.Success(fmt.Sprintf("Plaintext export created: %s", output))
	return 0
}

func exportPath(output, environment string) (string, error) {
	if output != "" {
		return output, nil
	}
	if environment == "" || strings.ContainsAny(environment, `/\`) || environment == "." || environment == ".." {
		return "", errUsage
	}
	return filepath.Join(".", ".env."+environment), nil
}

func (w Workspace) rotate(argv []string) int {
	a, err := parseArgs(argv, []string{"length"}, nil, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError("rotate <reference> [--length <n>]")
	}
	length := 0
	if raw, ok := a.options["length"]; ok {
		if length, err = strconv.Atoi(raw); err != nil {
			return w.usageError("rotate <reference> [--length <n>]")
		}
	}
	ref := a.positional[0]
	if length, err = w.Session.Rotate(ref, length); err != nil {
		return w.fail(err, "Secret could not be rotated.")
	}
	status := w.status()
	status.Success(fmt.Sprintf("Rotated %s to a new %d-character value. The previous value is kept; undo with `rollback %s`.", ref, length, ref))
	if usages, err := w.Session.Usage(ref); err == nil && len(usages) > 0 {
		status.Info("Restart what uses it:")
		for _, usage := range usages {
			fmt.Fprintf(w.Stdout, "%s %s %s\n", usage.ProjectPath, usage.Environment, usage.Variable)
		}
	}
	status.Info("If the value is issued by a provider, such as an API key, rotate it there and store it with `set` instead.")
	return 0
}

func (w Workspace) rollback(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("rollback <reference>")
	}
	if err := w.Session.Rollback(argv[0]); err != nil {
		return w.fail(err, "Secret could not be rolled back.")
	}
	w.status().Success(fmt.Sprintf("Restored the previous value of %s. Run rollback again to undo.", argv[0]))
	return 0
}

func (w Workspace) history(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("history <reference>")
	}
	info, err := w.Session.Info(argv[0])
	if err != nil {
		return w.fail(err, "Secret history is unavailable.")
	}
	fmt.Fprintf(w.Stdout, "current value, set %s\n", day(info.UpdatedAt))
	for i, replaced := range info.Previous {
		fmt.Fprintf(w.Stdout, "earlier value %d, replaced %s\n", i+1, replaced.Local().Format(time.DateTime))
	}
	return 0
}

func (w Workspace) passwd(argv []string) int {
	if len(argv) != 0 {
		return w.usageError("passwd")
	}
	path := w.Session.VaultPath()
	if path == "" {
		return w.fail(app.ErrNoVault, "")
	}
	current, err := w.ReadSecret("Current master password")
	if err != nil {
		return w.fail(err, "Secure interactive input is required.")
	}
	check, err := vault.Open(path, current)
	wipe(current)
	if err != nil {
		return w.fail(err, "The current master password is wrong.")
	}
	check.Close()
	password, err := readConfirmedValue(w.ReadSecret, "New master password")
	if err != nil {
		return w.fail(err, "Secure interactive input is required.")
	}
	defer wipe(password)
	if err := w.Session.ChangePassword(password); err != nil {
		return w.fail(err, "The master password could not be changed.")
	}
	w.status().Success("Master password changed. The recovery key, agent, and keychain still work.")
	return 0
}

func (w Workspace) recovery(argv []string) int {
	switch {
	case len(argv) == 0:
		has, err := w.Session.HasRecovery()
		if err != nil {
			return w.fail(err, "Recovery status is unavailable.")
		}
		if has {
			w.status().Success("A recovery key is set. Run `recovery reset` to replace it.")
		} else {
			w.status().Warn("No recovery key is set. Run `recovery reset` to create one.")
		}
		return 0
	case len(argv) == 1 && argv[0] == "reset":
		w.status().Warn("A new recovery key replaces the old one, which stops working.")
		if !w.confirm() {
			w.status().Error("Confirmation is required.")
			return 1
		}
		key, err := w.Session.ResetRecovery()
		if err != nil {
			return w.fail(err, "The recovery key could not be created.")
		}
		defer wipe(key)
		showRecoveryKey(w.Stdout, w.status(), key)
		return 0
	}
	return w.usageError("recovery [reset]")
}

func showRecoveryKey(out io.Writer, status Presenter, key []byte) {
	status.Warn("Write down this recovery key and keep it offline. It is shown only once.")
	fmt.Fprintf(out, "\n    %s\n\n", vault.FormatRecoveryKey(key))
	status.Info("If you forget the master password, run `envrune recover` and enter this key.")
}

func (w Workspace) unlock(argv []string) int {
	ttl, err := unlockTTL(argv)
	if err != nil {
		return w.usageError("unlock [--ttl 8h]")
	}
	return startAgent(w.Session, ttl, w.status())
}

func unlockTTL(argv []string) (time.Duration, error) {
	a, err := parseArgs(argv, []string{"ttl"}, nil, false)
	if err != nil || len(a.positional) != 0 {
		return 0, errUsage
	}
	ttl := 8 * time.Hour
	if raw, ok := a.options["ttl"]; ok {
		if ttl, err = time.ParseDuration(raw); err != nil || ttl <= 0 {
			return 0, errUsage
		}
	}
	return ttl, nil
}

func startAgent(session *app.Session, ttl time.Duration, status Presenter) int {
	path := session.VaultPath()
	if path == "" {
		status.Error(describe(app.ErrNoVault, ""))
		return 1
	}
	socket := agent.SocketPath(path)
	_ = agent.Stop(socket) // replace an earlier agent and its time limit
	key, err := session.Key()
	if err != nil {
		status.Error(describe(err, "The vault key is unavailable."))
		return 1
	}
	defer wipe(key)
	if err := agent.Start(socket, key, ttl); err != nil {
		status.Error(describe(err, "The agent could not start."))
		return 1
	}
	status.Success(fmt.Sprintf("Vault unlocked for new terminals until %s. Run `envrune lock` to lock it sooner.", time.Now().Add(ttl).Format("15:04")))
	return 0
}

func (w Workspace) ui(argv []string) int {
	start := w.StartUI
	if start == nil {
		start = executeSessionUI
	}
	return start(w.Session, argv, w.Stdout, w.Stderr)
}
