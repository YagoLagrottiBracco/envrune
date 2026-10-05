package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/agent"
	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/keychain"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

const helpText = `Usage: envrune <command> [arguments]

Start
  init                        Create the encrypted vault (shows a recovery key)
  project init [name]         Create envrune.yml in this directory
  shell                       Unlock once and run commands interactively
  ui                          Open the local, read-only dashboard

Secrets
  set <reference>             Store a value (asked twice, never echoed)
  generate <reference> [--length n]
  list [--long]               List references, with metadata when --long
  info <reference>            Show metadata, history size, and usage
  meta <reference> [--description t] [--owner o] [--expires YYYY-MM-DD]
  copy <reference> [--clear-after 30s]
  rotate <reference> [--length n]   Replace with a generated value
  rollback <reference>        Restore the previous value
  history <reference>         List when earlier values were replaced
  remove <reference>
  import <file.env>
  migrate [folder] [--siblings] [--env e]
                              Move .env files into the vault and envrune.yml

Projects
  link <VAR> <reference> [--env e]  Bind a variable; offers to create the secret
  setup [--env e]             Walk through the variables documented in envrune.yml
  usage <reference>           Show which projects use a reference
  diff <env> <env>            Compare the variables of two environments
  types [ts|python] [--output path]  Generate env.d.ts or a pydantic Settings class
  run [--env e] [--no-redact] [--restart-on-rotate] [--] <command>
  render <template> [--env e] [--as VAR] -- <command>   Fill in a template for one run
  check [name...] [--env e]   Run the project's checks that its secrets still work
                              Run a command; values it prints show as ****
  <name> [args]               Run a command defined under commands: in envrune.yml
  up [name...] [--env e]      Run several commands at once
  export [--env e] [--output path] [--force]
  doctor                      Check the vault, envrune.yml, and bindings

Leaks
  guard [--strict]            Block staged changes that contain vault values
  guard install|uninstall     Run guard before every commit in this repository
  scan [path...] [--no-history]  Find vault values in files and Git history

AI agents
  mcp [--allow-args]          MCP server: run named commands with masked output

Editors and prompts
  inspect [--dir folder]      Describe envrune.yml as JSON, without values
  status --format json|prompt Show the unlock state for editors and shell prompts

Unlocking
  unlock [--ttl 8h]           Keep the vault unlocked for new terminals
  lock                        Forget the unlocked key now
  keychain enable|disable     Unlock with the system keychain
  status                      Show how the vault is unlocked
  passwd                      Change the master password
  recovery [reset]            Show or replace the recovery key
  recover                     Reset a forgotten password with the recovery key
  backup [path]               Copy the encrypted vault
  restore <path> [--recovery] Replace the vault with a backup

Teams and CI
  team init|whoami|keygen|members|add|remove|set|unset|list
  pull vercel|1password [--env e] [options]   Copy values from a service into the vault
  push github|vercel [--env e] [options]      Copy an environment to a service
  env [--env e] [--format sh|fish|powershell|json] [--no-prompt]
                              Print variables for eval or the Node and Python packages
  hook bash|zsh|fish|powershell                  Print a terminal hook

EnvRune Cloud (end-to-end encrypted sharing; run envrune cloud for details)
  login [--server url]        Sign this vault in through the browser
  logout                      Forget the session; this device's keys stay
  cloud whoami|init|recover   Your account, this device, and their fingerprints
  cloud device|org|member|project|env ...  Devices, organizations, and members
  cloud set|copy|pull|sync|share|rotate ... Secrets, verified on this device
  cloud rotation <org>        Values someone who left could read, to replace
  cloud status <org/p/env>    Who already has the current values
  cloud token create|revoke   Machine tokens for CI
  cloud audit export|verify   The audit log, checked for edits and gaps

envrune version prints this version; with --check it asks GitHub whether a
newer one exists, which EnvRune never does by itself.

envrune --verbose <command>, or ENVRUNE_VERBOSE=1, prints each request to
EnvRune Cloud and its answer's status: never a header, a body, or a value.

Environment variables: ENVRUNE_VAULT, ENVRUNE_PASSWORD_FILE, ENVRUNE_PASSWORD,
ENVRUNE_IDENTITY, ENVRUNE_TOKEN, ENVRUNE_CLOUD_SERVER, ENVRUNE_VERBOSE,
NO_COLOR.
`

var builtinCommands = map[string]bool{
	"help": true, "version": true, "init": true, "project": true, "shell": true, "lock": true, "status": true,
	"keychain": true, "recover": true, "backup": true, "restore": true, "hook": true, "guard": true, "mcp": true, "inspect": true,
}

func isBuiltin(name string) bool { return builtinCommands[name] || isSessionCommand(name) }

func Execute(args []string, stdout, stderr io.Writer) int {
	verbose := os.Getenv("ENVRUNE_VERBOSE") != ""
	if len(args) > 0 && args[0] == "--verbose" {
		verbose, args = true, args[1:]
	}
	if verbose {
		traceCloud(stderr)
	}
	if len(args) < 1 {
		return executeOnboarding(stdout, stderr)
	}
	status := NewPresenter(stdout, stderr, os.Getenv)
	prompt := SecretPrompt{Output: stderr}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, helpText)
		return 0
	case "version", "--version":
		return executeVersion(args[1:], stdout, status)
	case "shell":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: envrune shell")
			return 2
		}
		return executeShell(stdout, stderr)
	case "init":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: envrune init")
			return 2
		}
		return executeInit(prompt.Read, stdout, status)
	case "project":
		return executeProjectInit(args[1:], status)
	case "lock":
		return executeLock(status)
	case "status":
		return executeStatus(args[1:], stdout, status)
	case "keychain":
		return executeKeychain(args[1:], prompt.Read, status)
	case "recover":
		return executeRecover(prompt.Read, status)
	case "backup":
		return executeBackup(args[1:], status)
	case "restore":
		return executeRestore(args[1:], prompt.Read, status)
	case "hook":
		return executeHook(args[1:], stdout, stderr)
	case "guard":
		return executeGuard(args[1:], stdout, stderr)
	case "mcp":
		return executeMCP(args[1:], stderr)
	case "inspect":
		return executeInspect(args[1:], stdout, stderr)
	case "diff", "types":
		// Reads only envrune.yml, so it needs no unlock.
		return Workspace{Stdout: stdout, Stderr: stderr}.Execute(args)
	case "cloud":
		// Checks files, or makes a key for a server: neither needs the vault.
		if len(args) > 2 && (args[1] == "audit" && args[2] == "verify" || args[1] == "proxy") {
			return Workspace{Stdout: stdout, Stderr: stderr}.Execute(args)
		}
	case "__project-root":
		return projectRoot(stdout)
	case "team":
		if len(args) == 2 && args[1] == "keygen" {
			return executeTeamKeygen(stdout, status)
		}
	}
	if !isSessionCommand(args[0]) && !isProjectCommand(args[0]) {
		fmt.Fprintln(stderr, "unknown command; run `envrune help`")
		return 2
	}
	// Reject malformed arguments before asking for the master password.
	if args[0] == "set" && len(args) != 2 && !(len(args) == 4 && (args[2] == "--file" || args[1] == "--file")) {
		fmt.Fprintln(stderr, "usage: envrune set <reference> [--file <path>]")
		return 2
	}
	if args[0] == "ui" {
		if _, _, err := uiArguments(args[1:]); err != nil {
			fmt.Fprintln(stderr, "usage: envrune ui [--port <port>] [--no-browser]")
			return 2
		}
	}
	// A terminal hook and the Node and Python packages must never wait for a
	// password; the hook also stays silent when the vault is locked.
	quiet := args[0] == "env" && containsArg(args, "--hook")
	noPrompt := quiet || args[0] == "env" && containsArg(args, "--no-prompt")
	session, err := unlocker{getenv: os.Getenv, prompt: prompt.Read, noPrompt: noPrompt, status: status}.session()
	if err != nil {
		if !quiet {
			status.Error(describe(err, "Unable to unlock the vault."))
		}
		return 1
	}
	defer session.Close()
	return Workspace{
		Session:    session,
		Stdout:     stdout,
		Stderr:     stderr,
		ReadSecret: prompt.Read,
		ReadChoice: ChoicePrompt{Output: stderr}.Read,
	}.Execute(args)
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func isProjectCommand(name string) bool {
	path, err := project.Find(".")
	if err != nil {
		return false
	}
	config, err := project.Load(path)
	if err != nil {
		return false
	}
	_, ok := config.Commands[name]
	return ok
}

func executeInit(read func(string) ([]byte, error), stdout io.Writer, status Presenter) int {
	path, err := vaultPath(os.Getenv)
	if err != nil {
		status.Error("Vault path is unavailable.")
		return 1
	}
	password, err := read("Master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	defer wipe(password)
	confirmation, err := read("Confirm master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	defer wipe(confirmation)
	recovery, err := (app.VaultService{}).Init(path, password, confirmation)
	if err != nil {
		status.Error(describe(err, "Vault initialization failed."))
		return 1
	}
	defer wipe(recovery)
	status.Success("Vault initialized.")
	showRecoveryKey(stdout, status, recovery, vaultRecoveryUse, vaultRecoveryAgain)
	return 0
}

func executeProjectInit(args []string, status Presenter) int {
	if len(args) < 1 || args[0] != "init" || len(args) > 2 {
		status.Error("Usage: envrune project init [name]")
		return 2
	}
	dir, err := os.Getwd()
	if err != nil {
		status.Error("The current directory is unavailable.")
		return 1
	}
	path := filepath.Join(dir, "envrune.yml")
	if _, err := os.Stat(path); err == nil {
		status.Error("envrune.yml already exists here.")
		return 1
	}
	name := filepath.Base(dir)
	if len(args) == 2 {
		name = args[1]
	}
	config := project.Config{Version: 1, Project: name, DefaultEnv: "development", Environments: map[string]map[string]domain.Reference{"development": {}}}
	if err := project.WriteAtomic(path, config); err != nil {
		status.Error(describe(err, "envrune.yml could not be created."))
		return 1
	}
	status.Success("Created envrune.yml with a development environment. Bind variables with `envrune link <VAR> <reference>`.")
	return 0
}

func executeLock(status Presenter) int {
	path, err := vaultPath(os.Getenv)
	if err != nil {
		status.Error("Vault path is unavailable.")
		return 1
	}
	if err := agent.Stop(agent.Address(path)); err != nil {
		status.Info("No unlock agent was running.")
	} else {
		status.Success("The agent forgot the vault key. New terminals will ask for the master password.")
	}
	if keychainEnabled(path) {
		status.Warn("The system keychain still unlocks the vault. Run `envrune keychain disable` to stop that.")
	}
	return 0
}

// vaultStatus is what `envrune status` reports. Gathering it never unlocks
// the vault, so it is fast enough for a shell prompt.
type vaultStatus struct {
	Vault            string    `json:"vault"`
	Exists           bool      `json:"exists"`
	Unlocked         bool      `json:"unlocked"` // an agent holds the key
	Expires          time.Time `json:"expires,omitzero"`
	RemainingSeconds int       `json:"remaining_seconds,omitempty"`
	Keychain         bool      `json:"keychain"`
	LockHolder       int       `json:"lock_holder,omitempty"`
	Project          string    `json:"project,omitempty"`
	DefaultEnv       string    `json:"default_env,omitempty"`
}

func readStatus(getenv func(string) string, dir string) (vaultStatus, error) {
	path, err := vaultPath(getenv)
	if err != nil {
		return vaultStatus{}, err
	}
	s := vaultStatus{Vault: path}
	if _, err := os.Stat(path); err == nil {
		s.Exists = true
	}
	if expires, err := agent.Status(agent.Address(path)); err == nil {
		s.Unlocked, s.Expires = true, expires
		s.RemainingSeconds = max(0, int(time.Until(expires).Seconds()))
	}
	s.Keychain = keychainEnabled(path)
	s.LockHolder = vault.LockHolder(path)
	if projectPath, err := project.Find(dir); err == nil {
		s.Project = projectPath
		if config, err := project.Load(projectPath); err == nil {
			if environment, err := app.ChooseEnvironment(config, ""); err == nil {
				s.DefaultEnv = environment
			}
		}
	}
	return s, nil
}

// promptWord is the short state a shell prompt shows.
func (s vaultStatus) promptWord() string {
	switch {
	case !s.Exists:
		return "no vault"
	case s.Unlocked:
		remaining := time.Duration(s.RemainingSeconds) * time.Second
		if remaining >= time.Hour {
			return fmt.Sprintf("unlocked %dh", int(remaining.Hours()))
		}
		return fmt.Sprintf("unlocked %dm", int(remaining.Minutes()))
	case s.Keychain:
		return "keychain"
	default:
		return "locked"
	}
}

func executeStatus(args []string, stdout io.Writer, status Presenter) int {
	a, err := parseArgs(args, []string{"format"}, []string{"always"}, false)
	format := a.options["format"]
	if err != nil || len(a.positional) != 0 || (format != "" && format != "text" && format != "json" && format != "prompt") {
		status.Error("Usage: envrune status [--format text|json|prompt] [--always]")
		return 2
	}
	s, err := readStatus(os.Getenv, ".")
	if err != nil {
		status.Error("Vault path is unavailable.")
		return 1
	}
	switch format {
	case "json":
		_ = json.NewEncoder(stdout).Encode(s)
		return 0
	case "prompt":
		// Outside a project the prompt stays clean, unless asked otherwise.
		if s.Project != "" || a.flags["always"] {
			fmt.Fprintln(stdout, s.promptWord())
		}
		return 0
	}
	fmt.Fprintf(stdout, "Vault:     %s\n", s.Vault)
	if !s.Exists {
		fmt.Fprintln(stdout, "           not created yet; run `envrune init`")
	}
	if s.Unlocked {
		fmt.Fprintf(stdout, "Agent:     unlocked until %s\n", s.Expires.Local().Format(time.DateTime))
	} else {
		fmt.Fprintln(stdout, "Agent:     locked")
	}
	if s.Keychain {
		fmt.Fprintln(stdout, "Keychain:  enabled")
	} else {
		fmt.Fprintln(stdout, "Keychain:  disabled")
	}
	if s.LockHolder != 0 {
		fmt.Fprintf(stdout, "File lock: held by PID %d\n", s.LockHolder)
	}
	if s.Project != "" {
		fmt.Fprintf(stdout, "Project:   %s\n", s.Project)
		if s.DefaultEnv != "" {
			fmt.Fprintf(stdout, "Default:   %s\n", s.DefaultEnv)
		}
	}
	return 0
}

func executeKeychain(args []string, read func(string) ([]byte, error), status Presenter) int {
	if len(args) != 1 || (args[0] != "enable" && args[0] != "disable") {
		status.Error("Usage: envrune keychain enable|disable")
		return 2
	}
	path, err := vaultPath(os.Getenv)
	if err != nil {
		status.Error("Vault path is unavailable.")
		return 1
	}
	account := keychain.Account(path)
	if args[0] == "disable" {
		_ = keychain.Delete(account)
		_ = os.Remove(keychainMarker(path))
		status.Success("The system keychain no longer unlocks the vault.")
		return 0
	}
	password, err := read("Master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	session, err := app.OpenSession(path, password)
	wipe(password)
	if err != nil {
		status.Error(describe(err, "Unable to unlock the vault."))
		return 1
	}
	defer session.Close()
	key, err := session.Key()
	if err != nil {
		status.Error(describe(err, "The vault key is unavailable."))
		return 1
	}
	defer wipe(key)
	if err := keychain.Set(account, key); err != nil {
		status.Error(describe(err, "The system keychain refused the key."))
		return 1
	}
	if err := os.WriteFile(keychainMarker(path), []byte("enabled\n"), 0600); err != nil {
		status.Error("The keychain setting could not be saved.")
		return 1
	}
	status.Success("New terminals now unlock the vault through your system login. Run `envrune keychain disable` to undo.")
	return 0
}

func executeRecover(read func(string) ([]byte, error), status Presenter) int {
	path, err := vaultPath(os.Getenv)
	if err != nil {
		status.Error("Vault path is unavailable.")
		return 1
	}
	text, err := read("Recovery key")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	key, err := vault.ParseRecoveryKey(string(text))
	wipe(text)
	if err != nil {
		status.Error(describe(err, "The recovery key is invalid."))
		return 1
	}
	defer wipe(key)
	opened, err := vault.OpenWithRecovery(path, key)
	if err != nil {
		status.Error(describe(err, "The recovery key does not open this vault."))
		return 1
	}
	session := app.NewSession(opened)
	defer session.Close()
	password, err := readConfirmedValue(read, "New master password")
	if err != nil {
		status.Error(describe(err, "Secure interactive input is required."))
		return 1
	}
	defer wipe(password)
	if err := session.ChangePassword(password); err != nil {
		status.Error(describe(err, "The master password could not be reset."))
		return 1
	}
	status.Success("Master password reset. Your recovery key still works.")
	return 0
}

func executeBackup(args []string, status Presenter) int {
	path, err := vaultPath(os.Getenv)
	if err != nil || len(args) > 1 {
		status.Error("Usage: envrune backup [path]")
		return 2
	}
	dest := ""
	if len(args) == 1 {
		dest = args[0]
	} else {
		dir := filepath.Join(filepath.Dir(path), "backups")
		if err := os.MkdirAll(dir, 0700); err != nil {
			status.Error("The backup directory could not be created.")
			return 1
		}
		dest = filepath.Join(dir, "vault-"+time.Now().Format("20060102-150405")+".ev1")
	}
	if err := vault.Backup(path, dest); err != nil {
		status.Error(describe(err, "The backup could not be written. Does the destination already exist?"))
		return 1
	}
	status.Success(fmt.Sprintf("Encrypted backup written to %s. It opens with the password and recovery key of this moment.", dest))
	return 0
}

func executeRestore(args []string, read func(string) ([]byte, error), status Presenter) int {
	a, err := parseArgs(args, nil, []string{"recovery"}, false)
	path, perr := vaultPath(os.Getenv)
	if err != nil || perr != nil || len(a.positional) != 1 {
		status.Error("Usage: envrune restore <backup> [--recovery]")
		return 2
	}
	backup := a.positional[0]
	if a.flags["recovery"] {
		text, err := read("Recovery key of the backup")
		if err != nil {
			status.Error(describe(err, "Secure interactive input is required."))
			return 1
		}
		key, err := vault.ParseRecoveryKey(string(text))
		wipe(text)
		if err == nil {
			err = vault.Verify(backup, nil, key)
			wipe(key)
		}
		if err != nil {
			status.Error(describe(err, "The backup does not open with that recovery key."))
			return 1
		}
	} else {
		password, err := read("Master password of the backup")
		if err != nil {
			status.Error(describe(err, "Secure interactive input is required."))
			return 1
		}
		err = vault.Verify(backup, password, nil)
		wipe(password)
		if err != nil {
			status.Error(describe(err, "The backup does not open with that password."))
			return 1
		}
	}
	status.Warn("The current vault will be replaced. A copy of it is saved first.")
	if !confirmWith(read) {
		status.Error("Confirmation is required.")
		return 1
	}
	if _, err := os.Stat(path); err == nil {
		saved := path + ".before-restore-" + time.Now().Format("20060102-150405")
		if err := vault.Backup(path, saved); err != nil {
			status.Error(describe(err, "The current vault could not be saved; nothing was restored."))
			return 1
		}
		status.Info(fmt.Sprintf("Current vault saved to %s.", saved))
	}
	if err := vault.Restore(path, backup); err != nil {
		status.Error(describe(err, "The backup could not be restored."))
		return 1
	}
	_ = agent.Stop(agent.Address(path))
	if keychainEnabled(path) {
		_ = keychain.Delete(keychain.Account(path))
		_ = os.Remove(keychainMarker(path))
		status.Info("Keychain unlock was turned off because the restored vault may use another key. Run `envrune keychain enable` again.")
	}
	status.Success("Vault restored.")
	return 0
}

func confirmWith(read func(string) ([]byte, error)) bool {
	value, err := read("Type YES to confirm")
	if err != nil {
		return false
	}
	defer wipe(value)
	return string(value) == "YES"
}

func insideGit(dir string) bool {
	return exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Run() == nil
}

func wipePairs(pairs []runner.Pair) {
	for _, pair := range pairs {
		wipe(pair.Value)
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
