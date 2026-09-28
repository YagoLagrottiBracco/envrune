# Envrune Native Windows Support and Complete README Design

## Goal

Make Envrune usable as a native `windows/amd64` executable from PowerShell or
Command Prompt, with no WSL and no Go installation required for people using a
published binary. Preserve the local-only vault model and document exactly what
is, and is not, protected on Windows and Linux.

The README becomes the complete user guide for the initial release: installation,
first use, commands, security, storage, backup, and troubleshooting. It remains
entirely in English, matching the CLI and UI.

## Scope and principles

- Support Linux `amd64` and Windows `amd64` as first-class release targets.
- Keep one encrypted file format across platforms; a vault file may be copied
  between supported systems when the same master password is known.
- Keep the foreground-only design: no account, daemon, socket, synchronization,
  telemetry, or secret-bearing temporary files.
- Never route `envrune run` through PowerShell, `cmd.exe`, or a Unix shell.
- Do not claim that Windows has Linux's `PR_SET_DUMPABLE` protection. The
  README must state this limitation plainly.

## Platform design

### Data locations

`paths.VaultPath` becomes platform-aware:

| Platform | Default vault path |
| --- | --- |
| Linux | `$XDG_DATA_HOME/envrune/vault.ev1`, or `~/.local/share/envrune/vault.ev1` |
| Windows | `%LOCALAPPDATA%\Envrune\vault.ev1`, or `%USERPROFILE%\AppData\Local\Envrune\vault.ev1` when `LOCALAPPDATA` is missing |

Paths use `filepath.Join`, never POSIX-only `path.Join`. Linux continues to
honor `XDG_DATA_HOME`; Windows deliberately uses its native per-user local-data
location.

### Locking and atomic writes

The current non-Linux no-op lock implementation is not sufficient for a
supported Windows vault. Windows-specific implementations will:

1. Acquire an exclusive advisory lock for the lifetime of an opened vault or
   project write, returning the existing safe generic error when another
   Envrune process owns it.
2. Replace a completed same-directory temporary file with the destination using
   the Windows replace-existing API and write-through semantics. It must not
   delete the old vault before a replacement is ready.
3. Share that atomic-replacement primitive between the vault, project
   configuration, and plaintext export writers, while retaining the current
   Linux behavior.

The data directory lives under the user's Local AppData profile, whose normal
Windows ACL isolates it from other non-administrator user accounts. Envrune
will not claim protection from an administrator, SYSTEM, kernel driver, or
malicious process running as the same user.

### Execution and browser behavior

On Windows, `envrune run --env <environment> -- <program> [args...]` starts the
requested executable directly through Go's process API. It supplies selected
variables only through the child environment and never writes an `.env` file or
evaluates a command in a shell.

Linux retains the self-exec path that marks the child non-dumpable immediately
before `exec`. Windows has no equivalent Envrune-managed primitive in this
release; direct execution still avoids shell history and temporary files, but a
privileged or same-user debugger remains outside Envrune's protection boundary.

`envrune ui` on Windows opens the supplied one-time loopback URL through the
native URL handler. The UI server, Host/Origin/CSRF checks, no-store headers,
and metadata-only responses are unchanged.

### Binaries and development

Release artifacts are named `envrune-linux-amd64` and `envrune-windows-amd64.exe`.
An end user downloads the matching binary and does not need Go. Building from
source remains documented for contributors and writes:

- `bin/envrune` for Linux;
- `bin/envrune.exe` for Windows.

Unsigned Windows binaries may trigger SmartScreen until the project establishes
a code-signing release process; the README will state that fact rather than ask
users to disable operating-system protections.

## README design

The README will be organized as a practical start-to-finish guide:

1. What Envrune does, its local-only model, and its supported platforms.
2. Install or run a prebuilt binary on Windows and Linux, plus optional
   build-from-source instructions.
3. First launch with `envrune`, the explicit vault-creation confirmation, and
   master-password behavior.
4. The recommended one-password `envrune shell` workflow and the complete
   command reference, including one-shot compatibility commands.
5. A minimal `envrune.yml` example using references only, never values.
6. Safe `run`, intentionally risky plaintext `export`, import confirmation,
   local UI behavior, colors, and `NO_COLOR`.
7. Storage locations, backup and restore of the encrypted vault, and the fact
   that a lost master password cannot be recovered.
8. A precise security model and platform-specific limits, followed by concise
   troubleshooting for missing binaries, locked vaults, and password failures.

All examples use placeholder references and variable names only. No example
will contain a secret value, recommend checking `.env` files into source
control, or present plaintext export as a persistent workflow.

## Errors and compatibility

- All platform-level failures are converted to existing generic, value-safe CLI
  messages. They must not include vault plaintext, master passwords, or child
  environment values.
- Existing Linux vault paths and command behavior remain compatible.
- A Windows vault created by this version uses the existing encrypted file
  format; no migration is required.
- Existing callers of `envrune init`, `envrune shell`, and the one-shot commands
  retain their interfaces.

## Verification

The implementation must include and run:

1. Unit tests for native path selection and no accidental POSIX paths on
   Windows.
2. Windows-host tests that prove lock contention rejects a second writer and
   repeated vault/project/export commits replace files successfully.
3. Existing Windows runner tests for direct child execution and exit-code
   propagation.
4. `go test ./...` on Windows, plus a Linux cross-build and a Windows native
   build.
5. README review against the actual command grammar and a scan confirming that
   examples contain no values or real credentials.

## Non-goals

- Cloud sync, organizations, web accounts, shared secrets, or remote storage.
- A Windows service, background key cache, keyring integration, or persistent
  unlocked session.
- Claiming a Windows equivalent of the Linux non-dumpable child process.
- Automatically importing, rewriting, or deleting users' existing `.env`
  files.
