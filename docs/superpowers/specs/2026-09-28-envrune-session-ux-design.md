# Envrune Session Shell and CLI Feedback Design

## Goal

Make Envrune pleasant to use during a local development session without
weakening its local-first security model. User-facing CLI and local UI text is
English. Interactive terminals receive clear, colored feedback; redirected
output remains plain and machine-safe.

## Scope

- Add `envrune shell`, an Envrune-owned interactive command shell.
- Prompt for the master password once when the shell starts.
- Keep the opened vault, derived key, and secret data only in that process's
  memory until the user runs `exit`, `lock`, or the process terminates.
- Make the shell support the existing operational commands: `set`, `list`,
  `link`, `usage`, `generate`, `import`, `run`, `export`, `ui`, and `help`.
- Keep `envrune init` as a standalone bootstrap command because no vault is
  available before initialization. Existing one-shot commands remain
  compatible and continue to request a password per invocation.
- Add concise success, information, warning, and error feedback throughout
  the command line and local UI.

## Explicit non-goals

- No persistent password, derived key, session token, or plaintext value.
- No background daemon, Unix socket, shell environment capability, or cache
  shared across terminals.
- No color escape sequences in redirected output, logs, HTTP responses, YAML,
  or exported dotenv files.
- No secret values in prompts, messages, errors, the shell history supplied by
  Envrune, or the local UI.

## Interaction design

`envrune shell` securely reads the master password once and opens the vault.
The password buffer is wiped immediately after opening. The prompt is:

```text
envrune [unlocked] >
```

`exit` and `lock` close the vault and return success only after sensitive
buffers have been wiped. EOF, Ctrl+C, and fatal initialization errors follow
the same cleanup path. `help` remains available without a password outside the
session and displays the session workflow.

The shell parses command words itself; it does not evaluate shell syntax,
substitutions, or expansions. It supports quoted arguments so a deliberate
`run --env dev -- ...` command can be forwarded without an intermediary shell.
The target program itself remains a direct child process of Envrune.

Destructive plaintext export still requires a typed `YES` confirmation and
uses the existing secure non-echoing input. This is deliberately separate from
the one-time password prompt.

## Vault-session architecture

`app.Session` owns one `vault.Opened` value. It exposes the existing vault
operations against that open value instead of reopening and re-deriving the
key for every shell command. Mutations commit atomically through the existing
vault writer. The vault lock is deliberately held for the entire shell
session, so a concurrent process cannot silently write stale vault data.

`vault.Opened.Close` is strengthened to wipe its derived key, every in-memory
secret byte slice, project metadata, and maps before releasing the lock.
`app.Session.Close` is idempotent and is always deferred by the interactive
shell.

The existing local UI starts from a session snapshot when invoked inside the
shell. It receives indexes and reference metadata only; values never become
HTTP data. Locking the UI ends its HTTP session but does not unlock the parent
CLI shell; exiting the CLI shell ends both resources.

## Visual feedback

A small CLI presentation layer emits these semantic message types:

- success: green `OK` marker for completed actions;
- information: blue marker for progress and locations;
- warning: yellow marker for deliberate plaintext export and confirmations;
- error: red marker for actionable failures.

Color is enabled only when the selected writer is a terminal, `NO_COLOR` is
absent, and the terminal is not `dumb`. Tests and redirected output receive
the same English text without ANSI sequences. Output reports counts, reference
names, environment names, and paths only where already safe; it never reports
values or master-password material.

The loopback UI keeps its dark presentation but adopts the same English terms
and semantic success/warning/error status treatment.

## Command outcomes

Successful commands explicitly acknowledge their outcome, for example:

- `Vault initialized.`
- `Secret stored: openai.demo`
- `Linked OPENAI_API_KEY for environment dev.`
- `Generated and stored a 48-character secret.`
- `Imported 3 secrets.`
- `Starting command with 2 injected variables.`
- `Exported 2 variables to .env.dev. This file contains plaintext secrets.`

Failure messages remain deliberately general around unlock, parsing, and
secret-resolution failures. They direct the user to the next safe action but
do not disclose secret content or supplied malformed values.

## Verification

Tests must prove that:

1. `envrune shell` reads the master password exactly once, reuses one opened
   vault for multiple commands, and wipes/closes it on every exit path.
2. A shell command can store, list, link, and run a configured variable while
   no value appears in captured output.
3. `lock`, `exit`, EOF, and interrupted shell cleanup make the session
   unusable.
4. ANSI styling occurs for a terminal writer only, respects `NO_COLOR`, and
   never appears in a captured or redirected writer.
5. All visible CLI text is English; success/error paths offer feedback without
   exposing passwords, values, YAML, or HTTP response data.
6. Existing one-shot behavior, atomic persistence, export confirmation, and
   loopback-UI security tests stay green.
