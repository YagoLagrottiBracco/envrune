package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

// env prints shell statements that set the resolved variables, for
// `eval "$(envrune env)"` and the terminal hook. It refuses to print to a
// terminal, where the values would be shown on screen.
func (w Workspace) env(argv []string) int {
	const usage = "env [--env <environment>] [--format sh|fish|powershell] [--hook]"
	a, err := parseArgs(argv, []string{"env", "format"}, []string{"hook"}, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError(usage)
	}
	format := a.options["format"]
	if format == "" {
		format = "sh"
	}
	if format != "sh" && format != "fish" && format != "powershell" {
		return w.usageError(usage)
	}
	if terminalWriter(w.Stdout) {
		w.status().Error("env prints secret values. Use it as eval \"$(envrune env)\" or through `envrune hook`.")
		return 2
	}
	_, resolved, err := w.resolve(a.options["env"])
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	writeAssignments(w.Stdout, format, resolved.Pairs, a.flags["hook"])
	return 0
}

func writeAssignments(out io.Writer, format string, pairs []runner.Pair, hook bool) {
	names := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		names = append(names, pair.Name)
		value := string(pair.Value)
		switch format {
		case "fish":
			fmt.Fprintf(out, "set -gx %s %s;\n", pair.Name, fishQuote(value))
		case "powershell":
			fmt.Fprintf(out, "$env:%s = %s\n", pair.Name, powershellQuote(value))
		default:
			fmt.Fprintf(out, "export %s=%s\n", pair.Name, shQuote(value))
		}
	}
	if !hook {
		return
	}
	list := strings.Join(names, " ")
	switch format {
	case "fish":
		fmt.Fprintf(out, "set -gx ENVRUNE_HOOK_VARS %s;\n", fishQuote(list))
	case "powershell":
		fmt.Fprintf(out, "$env:ENVRUNE_HOOK_VARS = %s\n", powershellQuote(list))
	default:
		fmt.Fprintf(out, "export ENVRUNE_HOOK_VARS=%s\n", shQuote(list))
	}
}

func shQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'" }

func fishQuote(value string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value) + "'"
}

func powershellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

// projectRoot prints the directory of the nearest envrune.yml, or nothing.
func projectRoot(out io.Writer) int {
	path, err := project.Find(".")
	if err != nil {
		return 1
	}
	fmt.Fprintln(out, filepath.Dir(path))
	return 0
}

const hookSh = `# EnvRune terminal hook: loads a project's variables when you enter its
# directory and removes them when you leave. It never asks for a password:
# run ` + "`envrune unlock`" + ` (or enable the keychain) first.
_envrune_hook() {
  local root
  root="$(envrune __project-root 2>/dev/null)"
  [ "$root" = "${ENVRUNE_HOOK_ROOT:-}" ] && return
  if [ -n "${ENVRUNE_HOOK_VARS:-}" ]; then
    for _envrune_var in $ENVRUNE_HOOK_VARS; do unset "$_envrune_var"; done
    unset _envrune_var
  fi
  unset ENVRUNE_HOOK_VARS ENVRUNE_HOOK_ROOT
  [ -z "$root" ] && return
  local statements
  if statements="$(envrune env --hook 2>/dev/null)"; then
    eval "$statements"
    export ENVRUNE_HOOK_ROOT="$root"
  fi
}
`

const hookBash = hookSh + `case ";${PROMPT_COMMAND:-};" in
  *";_envrune_hook;"*) ;;
  *) PROMPT_COMMAND="_envrune_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
`

const hookZsh = hookSh + `autoload -Uz add-zsh-hook
add-zsh-hook precmd _envrune_hook
`

const hookFish = `# EnvRune terminal hook: loads a project's variables when you enter its
# directory and removes them when you leave. Run envrune unlock first.
function _envrune_hook --on-event fish_prompt
  set -l root (envrune __project-root 2>/dev/null)
  if test "$root" = "$ENVRUNE_HOOK_ROOT"
    return
  end
  for var in (string split ' ' -- "$ENVRUNE_HOOK_VARS")
    test -n "$var"; and set -e $var
  end
  set -e ENVRUNE_HOOK_VARS
  set -e ENVRUNE_HOOK_ROOT
  test -z "$root"; and return
  set -l statements (envrune env --hook --format fish 2>/dev/null | string collect)
  and eval $statements
  and set -gx ENVRUNE_HOOK_ROOT $root
end
`

const hookPowerShell = `# EnvRune terminal hook: loads a project's variables when you enter its
# directory and removes them when you leave. Run envrune unlock first.
function global:_EnvruneHook {
  $root = (envrune __project-root 2>$null) | Select-Object -First 1
  if ("$root" -eq "$env:ENVRUNE_HOOK_ROOT") { return }
  if ($env:ENVRUNE_HOOK_VARS) {
    foreach ($var in $env:ENVRUNE_HOOK_VARS.Split(' ')) { Remove-Item "Env:$var" -ErrorAction SilentlyContinue }
  }
  Remove-Item Env:ENVRUNE_HOOK_VARS, Env:ENVRUNE_HOOK_ROOT -ErrorAction SilentlyContinue
  if (-not $root) { return }
  $statements = (envrune env --hook --format powershell 2>$null) -join [Environment]::NewLine
  if ($LASTEXITCODE -eq 0 -and $statements) {
    Invoke-Expression $statements
    $env:ENVRUNE_HOOK_ROOT = $root
  }
}
if (-not $global:_EnvruneOriginalPrompt) { $global:_EnvruneOriginalPrompt = $function:prompt }
function global:prompt { _EnvruneHook; & $global:_EnvruneOriginalPrompt }
`

func executeHook(args []string, stdout, stderr io.Writer) int {
	scripts := map[string]string{"bash": hookBash, "zsh": hookZsh, "fish": hookFish, "powershell": hookPowerShell, "pwsh": hookPowerShell}
	if len(args) != 1 || scripts[args[0]] == "" {
		fmt.Fprintln(stderr, "usage: envrune hook bash|zsh|fish|powershell")
		return 2
	}
	fmt.Fprint(stdout, scripts[args[0]])
	return 0
}
