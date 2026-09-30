package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
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

Projects
  link <VAR> <reference> [--env e]  Bind a variable; offers to create the secret
  usage <reference>           Show which projects use a reference
  run [--env e] [--] <command>      Run a command with the environment
  <name> [args]               Run a command defined under commands: in envrune.yml
  up [name...] [--env e]      Run several commands at once
  export [--env e] [--output path] [--force]
  doctor                      Check the vault, envrune.yml, and bindings

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
  push github [--env e] [--repo owner/name] [--github-env name]
  env [--env e] [--format sh|fish|powershell]   Print variables for eval
  hook bash|zsh|fish|powershell                  Print a terminal hook

Environment variables: ENVRUNE_VAULT, ENVRUNE_PASSWORD_FILE, ENVRUNE_PASSWORD,
ENVRUNE_IDENTITY, NO_COLOR.
`

var builtinCommands = map[string]bool{
	"help": true, "init": true, "project": true, "shell": true, "lock": true, "status": true,
	"keychain": true, "recover": true, "backup": true, "restore": true, "hook": true,
}

func isBuiltin(name string) bool { return builtinCommands[name] || isSessionCommand(name) }

func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		return executeOnboarding(stdout, stderr)
	}
	status := NewPresenter(stdout, stderr, os.Getenv)
	prompt := SecretPrompt{Output: stderr}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, helpText)
		return 0
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
		return executeStatus(stdout, status)
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
	if args[0] == "set" && len(args) != 2 {
		fmt.Fprintln(stderr, "usage: envrune set <reference>")
		return 2
	}
	if args[0] == "ui" {
		if _, _, err := uiArguments(args[1:]); err != nil {
			fmt.Fprintln(stderr, "usage: envrune ui [--port <port>] [--no-browser]")
			return 2
		}
	}
	noPrompt := args[0] == "env" && containsArg(args, "--hook")
	session, err := unlocker{getenv: os.Getenv, prompt: prompt.Read, noPrompt: noPrompt, status: status}.session()
	if err != nil {
		if !noPrompt {
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
	showRecoveryKey(stdout, status, recovery)
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
	if err := agent.Stop(agent.SocketPath(path)); err != nil {
		status.Info("No unlock agent was running.")
	} else {
		status.Success("The agent forgot the vault key. New terminals will ask for the master password.")
	}
	if keychainEnabled(path) {
		status.Warn("The system keychain still unlocks the vault. Run `envrune keychain disable` to stop that.")
	}
	return 0
}

func executeStatus(stdout io.Writer, status Presenter) int {
	path, err := vaultPath(os.Getenv)
	if err != nil {
		status.Error("Vault path is unavailable.")
		return 1
	}
	fmt.Fprintf(stdout, "Vault:     %s\n", path)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(stdout, "           not created yet; run `envrune init`")
	}
	if expires, err := agent.Status(agent.SocketPath(path)); err == nil {
		fmt.Fprintf(stdout, "Agent:     unlocked until %s\n", expires.Local().Format(time.DateTime))
	} else {
		fmt.Fprintln(stdout, "Agent:     locked")
	}
	if keychainEnabled(path) {
		fmt.Fprintln(stdout, "Keychain:  enabled")
	} else {
		fmt.Fprintln(stdout, "Keychain:  disabled")
	}
	if holder := vault.LockHolder(path); holder != 0 {
		fmt.Fprintf(stdout, "File lock: held by PID %d\n", holder)
	}
	if projectPath, err := project.Find("."); err == nil {
		fmt.Fprintf(stdout, "Project:   %s\n", projectPath)
		if config, err := project.Load(projectPath); err == nil {
			if environment, err := app.ChooseEnvironment(config, ""); err == nil {
				fmt.Fprintf(stdout, "Default:   %s\n", environment)
			}
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
	_ = agent.Stop(agent.SocketPath(path))
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
