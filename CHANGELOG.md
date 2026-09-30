# Changelog

All notable changes to EnvRune are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Upgrading

- **The vault file format is now version 2.** The first command that opens a
  0.1.0 vault converts it; after that, EnvRune 0.1.0 can no longer open it.
  Back up the vault file before upgrading. `envrune.yml` files from 0.1.0
  work unchanged.
- The Go module is now `github.com/YagoLagrottiBracco/envrune`, so
  `go install github.com/YagoLagrottiBracco/envrune/cmd/envrune@latest` works.

### Added

- **`envrune guard`** blocks a commit whose staged changes add a vault or team
  value, naming the file, line, and reference. `guard install` adds it as a
  pre-commit hook; with the vault locked it warns, or blocks with `--strict`.
- **`envrune scan`** finds vault and team values in files, logs, and every
  commit on every branch, and exits with code 1 when it finds one.
- **`variables:`** in `envrune.yml` documents each variable (description,
  how to get it, type, format, required). `envrune setup` walks a developer
  through them, and `run`, `up`, `env`, and `export` refuse values that do not
  fit, naming the variable and the rule.
- **Output masking:** `run`, named commands, and `up` replace any value a
  child prints with `****`, including URL-encoded and base64 forms and values
  split across writes. In a terminal the child gets a pseudo-terminal (pty on
  Linux and macOS, ConPTY on Windows), so colors and prompts keep working.
  `--no-redact` turns it off, and `doctor` lists values too short to mask.
- **Unlock once:** `envrune unlock --ttl 8h` starts an agent, like
  `ssh-agent`, that new terminals use instead of asking for the password.
  `envrune lock` and `envrune status` end it and show it. On Windows the
  agent listens on a named pipe that only your user can open.
- **System keychain unlock**, by explicit opt-in: `envrune keychain enable`
  stores the vault key in Windows Credential Manager, the macOS Keychain, or
  the Secret Service on Linux.
- **`default_env`** in `envrune.yml`, so `--env` can be left out.
- **Named commands:** a `commands:` section, run with `envrune <name>`.
- **`envrune up`** starts several commands with one unlock, with each
  service's output prefixed and colored. A command with `project:` uses
  another folder's `envrune.yml`, so services can keep their own files.
- **`envrune doctor`** checks links, the lock, the agent, forgotten `.env`
  files, lines in `envrune.yml` that look like values, and each
  `envrune.yml` that commands point to.
- `link` offers to store a reference that does not exist yet.
- **`envrune copy <ref>`** copies a value and clears the clipboard after 30
  seconds (`--clear-after`), only if it still holds that value.
- **Shell integration:** `envrune hook bash|zsh|fish|powershell` loads
  variables when you enter a project, and `envrune env` prints them.
- **Recovery key**, shown once by `envrune init`, with `envrune recover`,
  `envrune passwd`, `envrune backup`, and `envrune restore`.
- **History and rotation:** `rotate`, `rollback`, and `history` keep the last
  five values of each secret, encrypted. `meta` and `list --long` record a
  description, owner, and expiry, and `doctor` warns about expired and old
  secrets.
- **Team secrets:** `envrune.team.json` encrypts shared secrets to each
  member's public key and can be committed. `team.*` references read from it.
- **CI:** `ENVRUNE_PASSWORD`, `ENVRUNE_PASSWORD_FILE`, `ENVRUNE_VAULT`,
  `ENVRUNE_IDENTITY`, `envrune team keygen`, and `envrune push github`.
- Examples for VS Code (`launch.json`, `tasks.json`) and Docker Compose, and
  guides for the daily workflow, integrations, teams and CI, and WSL.
- Packages for Homebrew, Scoop, winget, and apt in the release workflow.
- A `ci` workflow that runs vet, the unit tests, and CLI integration tests on
  Linux, macOS, and Windows.

### Changed

- The vault is locked only while it is read or written, not for a whole
  session, so several shells and `run` commands can use it at once. A write
  first merges what other processes wrote.
- `set` asks for the value twice and refuses pasted text with several lines.
- Errors say what is missing, such as
  `Secret reference does not exist: demo.database-url (used by DATABASE_URL)`
  or `Environment "production" does not exist; available: development.`

### Fixed

- `run` finds commands on `PATH` on Linux, so `run -- python` works.
- A failing child is reported, with `command not found: X` or its exit code,
  in `envrune shell` too.
- A wrong password and a vault in use by another process (with its PID) get
  different messages.
- `envrune up` stops the processes a service started even after the service
  itself exited, on Windows too.
- `install.sh` creates a writable install directory without `sudo`.

## [0.1.0] - 2026-09-29

First release.

[Unreleased]: https://github.com/YagoLagrottiBracco/envrune/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YagoLagrottiBracco/envrune/releases/tag/v0.1.0
