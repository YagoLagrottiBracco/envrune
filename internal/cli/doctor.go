package cli

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/agent"
	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

func (w Workspace) doctor(argv []string) int {
	if len(argv) != 0 {
		return w.usageError("doctor")
	}
	var findings []app.Finding
	add := func(level app.Level, format string, args ...any) {
		findings = append(findings, app.Finding{Level: level, Message: fmt.Sprintf(format, args...)})
	}
	if path := w.Session.VaultPath(); path != "" {
		add(app.LevelOK, "vault: %s", path)
		switch holder := vault.LockHolder(path); {
		case holder > 0:
			add(app.LevelWarn, "the vault file is locked right now by PID %d", holder)
		case holder < 0:
			add(app.LevelWarn, "the vault file is locked right now by another process")
		}
		if expires, err := agent.Status(agent.SocketPath(path)); err == nil {
			add(app.LevelOK, "agent: unlocked until %s", expires.Local().Format(time.DateTime))
		}
		if keychainEnabled(path) {
			add(app.LevelOK, "system keychain unlock is enabled")
		}
	} else {
		add(app.LevelOK, "running from ENVRUNE_IDENTITY without a personal vault")
	}
	projectPath, err := w.findProject()
	if err != nil {
		add(app.LevelWarn, "no envrune.yml in this directory or its parents; run `envrune project init` to create one")
	} else {
		findings = append(findings, app.CheckProject(projectPath)...)
		if config, err := project.Load(projectPath); err == nil {
			var names []string
			for name := range config.Commands {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if isBuiltin(name) {
					add(app.LevelWarn, "commands.%s has the name of a built-in command; run it with `envrune run` or rename it", name)
				}
			}
			findings = append(findings, w.Session.CheckSecrets(projectPath, time.Now())...)
		}
	}
	report := NewPresenter(w.Stdout, w.Stdout, os.Getenv)
	errorsFound := 0
	for _, finding := range findings {
		switch finding.Level {
		case app.LevelOK:
			report.Success(finding.Message)
		case app.LevelWarn:
			report.Warn(finding.Message)
		default:
			report.Error(finding.Message)
			errorsFound++
		}
	}
	if errorsFound > 0 {
		return 1
	}
	return 0
}
