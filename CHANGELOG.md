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

- **Replaced values reach running commands.** A command started with `run`
  or by name says when a value it was started with has been replaced, in the
  vault, the team file, or the cloud, and `--restart-on-rotate` stops it and
  starts it again with the new value. With EnvRune Cloud, `run`, named
  commands, and `up` also ask the server for version numbers before they
  start and pull what changed, so nobody has to run `cloud pull` after a
  rotation. `cloud status <env>` shows which devices and tokens already have
  the current values, `cloud set --transition 24h` records how long the
  previous value keeps working, and commands a consumer runs are noted and
  reported to the audit log as `secret.use`.
- **Running a team on EnvRune Cloud** (`docs/cloud-operations.md`):
  - **A lost device:** `cloud device revoke`, or the panel, cuts it off;
    the CLI starts new keys for what it held, and what it fetched is listed
    to replace.
  - **A compromised project:** `cloud emergency <org/project>` revokes the
    tokens that reach it and takes its keys from every device but the
    owner's, until they are shared again.
  - **Rules:** `cloud policy set <org> <file>` denies roles an environment
    whatever their scope, such as consumers in production; owners and
    machine tokens are never denied.
  - **Notifications:** `cloud webhook set <org> <address>` has the server
    post each event, signed, to an address of yours. Events hold names,
    never values.
  - **Access for a limited time:** `cloud access request`, `approve`, and
    `end`. The server stops serving it by itself when the time is up.
- **More in envrune.yml** (`docs/project-file.md`), each a new key that
  leaves existing files as they were:
  - `extends:` lets an environment build on another, and `workspace:` lets
    a package of a monorepo start from the root's environments.
  - `envrune.local.yml` holds one developer's own overrides, outside Git;
    `envrune link --local` writes it.
  - `files:` delivers a secret as a file for the length of one command, for
    certificates, keys, and credentials files; `envrune set --file` stores
    one.
  - `render:` and `envrune render` fill in a configuration template with
    the environment's values, in a file that never lands in the project.
  - `checks:` and `envrune check` run the project's own tests that its
    secrets still work.
- **`envrune doctor`** lists the secrets no command used in 90 days and no
  project links, and `usage` shows the last day a secret was used.
- **`run` and named commands survive Ctrl+C** long enough to remove what
  they wrote for the command; the command itself still receives it.
- **Sensitive secrets** (EnvRune Cloud): a value that members use without
  it ever reaching their machine. An owner or admin marks it with
  `cloud set --sensitive --allow-host <host>`; `run` and named commands
  give the program a placeholder, and its HTTPS requests to the allowed
  hosts go through the server, which puts the value in. It works for any
  service and knows none. The server can read such a secret, the one
  exception to zero-knowledge, chosen per secret and only on a server
  that has a proxy identity (`envrune cloud proxy keygen`). A sensitive
  secret can also be a client certificate with its key, which the server
  presents to the allowed hosts. `run`, named commands, `up`, `render`,
  `check`, and the MCP server all set it up. See `docs/managed-keys.md`.
- **EnvRune Cloud** (optional): share secrets between the members of a team
  and with CI through a server that stores only ciphertext. There is no
  hosted service yet; run the server yourself (`docs/self-hosting.md`) and
  sign in with `envrune login --server <url>`. `docs/cloud.md` is the guide
  and `docs/cloud-crypto.md` the design, including what a compromised server
  can and cannot do.
  - **Accounts and devices:** `envrune cloud init` creates your keys and
    shows a recovery key once; a new device is approved from one you already
    use after comparing a fingerprint on both, or restored with
    `envrune cloud recover`.
  - **Organizations, projects, environments, and roles** (owner, admin,
    maintainer, consumer, auditor), with scopes per project and environment.
    Members are added after the admin compares their account fingerprint,
    and join with `envrune cloud org join --fingerprint`, which trusts the
    organization only if it is the one they were told about. Up to two more
    root holders can be named when an organization is created.
  - **Secrets:** `cloud set` (or `--generate`), `pull`, `sync`, `copy`, and
    `cloud.` references in `envrune.yml` after linking it with `cloud:
    org/project`. Devices verify who wrote each value and who shared each
    key, refuse an older version than one they have seen, and keep working
    offline with the last synced copy; an organization can limit for how
    long (`cloud org set --offline-days`).
  - **Consumers** can run programs with values but not see them: output
    stays masked, and `export`, `env`, `copy`, `push`, and
    `mcp --allow-any-command` refuse. This prevents accidents, not a
    determined consumer.
  - **CI:** `cloud token create` makes a machine token scoped to
    environments, with an expiry. With `ENVRUNE_TOKEN` and
    `ENVRUNE_CLOUD_SERVER`, `envrune run` needs no vault, and verifies
    everything against root keys the token carries.
  - **Leaving:** removing a member starts a new key for every environment
    they could use and signs again what they had signed. `cloud rotation`
    then lists every value they fetched until each is replaced or accepted
    as it is; the panel shows the same list.
  - **Audit log:** every fetch, write, rotation, and membership change, in a
    hash chain. `cloud audit export` verifies it and remembers its last
    entry, and `cloud audit verify` checks an export offline.
  - **Moving in:** `cloud import-team` moves `envrune.team.json` to a cloud
    environment and can point `envrune.yml` at it.
  - **Self-hosting:** a Docker image for the server, configured when it
    starts, next to a self-hosted or hosted Supabase.
- **`envrune guard`** blocks a commit whose staged changes add a vault or team
  value, naming the file, line, and reference. `guard install` adds it as a
  pre-commit hook; with the vault locked it warns, or blocks with `--strict`.
- **docs/why-envrune.md**: a two-minute migration, a comparison with dotenv,
  the 1Password CLI, Doppler, and Infisical with sources, and when to choose
  something else; **docs/demo-script.md**: a script and VHS tape for the demo
  GIF.
- **VS Code extension** in `packages/vscode` (not yet on the Marketplace): a
  status bar item with the unlock state, a view of projects, environments,
  variables, and commands, warnings on unlinked `process.env` and `os.environ`
  reads with a quick fix, and `"envrune": true` in `launch.json` to debug with
  the vault. An end-to-end test runs it in a real VS Code.
- **`envrune status --format json|prompt`** and **`envrune inspect`** describe
  the unlock state and `envrune.yml` for editors and shell prompts, without
  values or prompts. The prompt word is empty outside projects
  (`--always` shows it everywhere); `docs/prompt.md` has Starship and Oh My
  Posh setups.
- **`envrune pull` and `envrune push`** with providers: pull from Vercel (REST
  API, `VERCEL_TOKEN`) and 1Password (`op`), push to Vercel and GitHub Actions.
  `pull` shows new, changed, and unchanged variables without values, and
  stores and links them after confirmation; `push github` keeps working.
- **Packages for Node and Python** in `packages/` (not yet published) replace
  dotenv: `import "envrune/config"` and `envrune.load()` load variables from
  the vault through `envrune env --format json --no-prompt`, which is new, and
  fail clearly when the vault is locked instead of reading a `.env` file.
- **`envrune mcp`** is an MCP server for AI agents (Claude Code, Cursor, Copilot)
  with tools that list environments, variables, and commands, run the commands
  under `commands:` with output masked against every vault value, and run
  `doctor`. No tool returns a value; it never prompts, re-checks the unlock on
  every call, stops commands at a timeout, and allows extra arguments or any
  command only with `--allow-args` or `--allow-any-command`.
- **`envrune scan`** finds vault and team values in files, logs, and every
  commit on every branch, and exits with code 1 when it finds one.
- **`envrune migrate`** moves the `.env` files of a project, or of its sibling
  folders, into the vault and `envrune.yml`: it shows the plan without values,
  offers a shared reference for values several projects use, never overwrites
  a different vault value, updates `.gitignore`, and offers to delete the files.
  It reads the dotenv syntax Node and Python libraries accept.
- **`variables:`** in `envrune.yml` documents each variable (description,
  how to get it, type, format, required). `envrune setup` walks a developer
  through them, and `run`, `up`, `env`, and `export` refuse values that do not
  fit, naming the variable and the rule.
- **`envrune types`** generates `env.d.ts` for TypeScript or a pydantic-settings
  `Settings` class for Python from `variables:`.
- **`envrune diff <env> <env>`** lists the variables only one environment
  defines and those both point at the same reference, without unlocking.
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
