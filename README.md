<p align="center">
  <img src="docs/assets/envrune-mark.svg" width="112" alt="EnvRune rune mark">
</p>

<h1 align="center">EnvRune</h1>

<p align="center">
  A deliberate command-line workspace for encrypted environment variables.
</p>

<p align="center">
  <a href="#get-started">Get started</a>
  &nbsp;•&nbsp;
  <a href="#documentation">Documentation</a>
  &nbsp;•&nbsp;
  <a href="#building-from-source">Build</a>
  &nbsp;•&nbsp;
  <a href="#security-at-a-glance">Security</a>
  &nbsp;•&nbsp;
  <a href="#releases">Releases</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-5b5bd6?style=flat-square" alt="Apache-2.0 license"></a>
  <img src="https://img.shields.io/badge/Go-1.27-00ADD8?style=flat-square&amp;logo=go" alt="Go 1.27">
  <a href="#releases"><img src="https://img.shields.io/badge/status-pre--release-f2a43a?style=flat-square" alt="Pre-release status"></a>
</p>

EnvRune keeps secret values in an encrypted vault and lets projects refer to
them by name. A small, versionable `envrune.yml` describes which reference is
injected into which environment variable; the secret value never belongs in
that file.

It is designed for a calm workflow: unlock once in an interactive session,
manage references without printing their values, and launch the command that
needs them directly.

## What it gives you

| | Capability | What it means in practice |
| --- | --- | --- |
| **Vault** | Encrypted secret storage | Store values behind readable references such as `payments.development`. |
| **Projects** | Versionable bindings | Keep variable-to-reference mappings in `envrune.yml`, with no plaintext values. |
| **Runtime** | Direct process launch | Inject an environment into one child process with `envrune run`, a named command such as `envrune dev`, or several services at once with `envrune up`. |
| **Unlock** | One password a day | `envrune unlock --ttl 8h` or the system keychain unlocks every terminal, editor, and hook. |
| **Teams** | Shared secrets without a server | Commit `envrune.team.json`, encrypted to each member's key; CI gets its own identity. |
| **Safety net** | Recovery, history, doctor | A recovery key, encrypted backups, rotation with rollback, and `envrune doctor` for forgotten `.env` files. |
| **Overview** | Local dashboard | Inspect references and project bindings without exposing values in the browser. |

## Get started

### 1. Install the CLI

Download the installer for your system from the
[latest release](https://github.com/YagoLagrottiBracco/envrune/releases/latest):

| System | Download | How to install |
| --- | --- | --- |
| **Windows** | `envrune_<version>_windows_setup.exe` | Run it. It installs for your user (no administrator prompt) and adds `envrune` to your `PATH`. |
| **macOS** | `envrune_<version>_macos_universal.pkg` | Open it and follow the installer. Works on Apple Silicon and Intel. |
| **Debian / Ubuntu** | `envrune_<version>_linux_<arch>.deb` | `sudo apt install ./envrune_<version>_linux_amd64.deb` |
| **Fedora / RHEL** | `envrune_<version>_linux_<arch>.rpm` | `sudo dnf install ./envrune_<version>_linux_amd64.rpm` |

Package managers, once they are set up for the project (see
[Distribution](docs/distribution.md)):

```sh
brew install --cask yagolagrottibracco/tap/envrune       # macOS
winget install YagoLagrottiBracco.EnvRune                # Windows
scoop bucket add envrune https://github.com/YagoLagrottiBracco/scoop-bucket && scoop install envrune
```

On macOS or Linux you can also install with one command:

```sh
curl -fsSL https://raw.githubusercontent.com/YagoLagrottiBracco/envrune/main/install.sh | sh
```

Then open a new terminal and check it:

```sh
envrune --help
```

The installers are not code-signed yet. On Windows, SmartScreen may ask you to
choose **More info → Run anyway**; on macOS, a blocked `.pkg` can be allowed
from **System Settings → Privacy & Security → Open Anyway**. Portable archives
(`.zip` / `.tar.gz`) and a `checksums.txt` file are attached to every release.

Or build from a source checkout with Go 1.27:

```sh
go build -trimpath -o bin/envrune ./cmd/envrune
```

Run it from the repository root. Before managing another project, place the
binary on your `PATH` or use the absolute path to this `bin/envrune` file. The
examples below use `envrune` so they work from the project directory.

If your Go binary directory is already on `PATH`, Go can install the command
for you instead:

```sh
go install github.com/YagoLagrottiBracco/envrune/cmd/envrune@latest
envrune --help
```

### 2. Create your vault

Run EnvRune with no command and follow the secure terminal prompts:

```sh
envrune
```

It asks for explicit confirmation before creating a vault, then asks you to
set and confirm a master password. That password is not stored. EnvRune then
shows a **recovery key** once: write it down and keep it offline, because it
is the only way back in if you forget the password.

### 3. Bind a project

From the root of a project, create an `envrune.yml`. It contains only
metadata:

```sh
envrune project init
```

```yaml
version: 1
project: example-service
default_env: development
environments:
  development: {}
```

Unlock for the day, bind a variable (EnvRune offers to store the value when
the reference is new), and run your application:

```sh
envrune unlock --ttl 8h
envrune link SERVICE_TOKEN service.development
envrune run -- ./your-application
```

Name the commands you run often in `envrune.yml` and start them with
`envrune dev`, or start several at once with `envrune up`. See
[Getting started](docs/getting-started.md) and
[Daily workflow](docs/daily-workflow.md).

## A focused workflow

```text
secret value ──> encrypted vault ──> named reference ──> envrune.yml ──> child process
                                  never a plaintext value
```

The vault is the source of truth for values. Project files only map a process
variable, such as `SERVICE_TOKEN`, to a vault reference, such as
`service.development`. This makes project configuration reviewable without
turning it into a secret-bearing file.

## Commands at a glance

| Command | Use it for |
| --- | --- |
| `unlock [--ttl 8h]` / `lock` | Unlock the vault for new terminals for a while, or forget the key now. |
| `keychain enable` | Unlock through Windows Credential Manager, the macOS Keychain, or libsecret. |
| `shell` | Open one foreground session and enter the master password once. |
| `set <reference>` | Store or replace a value through a hidden prompt, asked twice. |
| `list [--long]` / `info` / `usage <reference>` | Review references, their metadata, and where they are bound. |
| `link <VAR> <reference> [--env e]` | Add a binding to the nearest `envrune.yml`, and offer to store a new value. |
| `migrate [--siblings]` | Move `.env` files into the vault and `envrune.yml`, after showing the plan. |
| `setup [--env e]` | Walk through the variables documented in `envrune.yml`, storing and linking each one. |
| `diff <env> <env>` | Compare the variables two environments define, by name only. |
| `types [ts\|python]` | Generate `env.d.ts` or a pydantic `Settings` class from `variables:`. |
| `run [--env e] [--no-redact] -- <command>` | Start one direct child process with resolved variables; values it prints show as `****`. |
| `<name>` / `up` | Run a command from `commands:` in `envrune.yml`, or several at once. |
| `copy <reference>` | Copy a value to the clipboard; cleared after 30 seconds. |
| `rotate` / `rollback` / `history` | Replace a value and keep the previous ones. |
| `doctor` | Find missing references, forgotten `.env` files, and pasted values. |
| `guard install` | Block commits that stage a vault value. |
| `scan [path...]` | Find vault values already in files, logs, and Git history. |
| `mcp` | MCP server for AI agents: run named commands with masked output, never read values. |
| `team …` / `push github` | Share secrets through `envrune.team.json`; feed CI. |
| `recover` / `backup` / `restore` | Reset a forgotten password with the recovery key; keep encrypted copies. |
| `export [--env e] [--output path] [--force]` | Deliberately create a plaintext dotenv file after confirmation. |
| `ui [--port <port>] [--no-browser]` | Start the metadata-only local dashboard. |

Run `envrune help` for every command and option. Every command also works
inside `envrune shell`. Set `NO_COLOR=1` for plain terminal output; redirected
output is already plain.

## Documentation

| Guide | Read it when you want to… |
| --- | --- |
| [Getting started](docs/getting-started.md) | Build EnvRune, create a vault, and connect a first project. |
| [Moving from .env files](docs/migrate.md) | Import every `.env` file of a project, or of several, with `envrune migrate`. |
| [Daily workflow](docs/daily-workflow.md) | Unlock once, use a default environment, named commands, `up`, `copy`, `doctor`, rotation, and recovery. |
| [Advanced usage](docs/advanced-usage.md) | Work with environments, imports, exports, generated values, and sessions. |
| [Integrations](docs/integrations.md) | Use EnvRune from VS Code, Docker Compose, and a direnv-style terminal hook. |
| [Documented variables](docs/variables.md) | Describe each variable, validate values, and onboard with `envrune setup`. |
| [Keeping values out of Git](docs/guard.md) | Block commits that contain vault values, and find old leaks. |
| [AI agents](docs/mcp.md) | Let Claude Code, Cursor, or Copilot run commands with secrets they cannot read. |
| [Replacing dotenv in code](docs/packages.md) | Load variables from the vault in Node or Python, like dotenv. |
| [Teams and CI](docs/teams-and-ci.md) | Share secrets with a team file and give pipelines access. |
| [Windows and WSL](docs/wsl.md) | Keep one vault or two across Windows and WSL. |
| [Local dashboard](docs/local-ui.md) | Understand the loopback UI, its token flow, and its limits. |
| [Security model](docs/security.md) | Review encryption, the agent and keychain, team files, and operating guidance. |
| [Building from source](docs/building.md) | Run checks and produce a local CLI binary. |
| [Distribution](docs/distribution.md) | Set up Homebrew, Scoop, winget, and apt publishing (maintainers). |

## Security at a glance

- The vault uses Argon2id for password derivation and XChaCha20-Poly1305 for
  authenticated encryption.
- The master password is never persisted. Values are encrypted under a random
  data key, wrapped by the password and by a recovery key shown once.
- Unlocking for later is opt-in: the agent keeps the data key in memory for a
  time limit you choose, and the keychain stores it under your system login.
- `run` launches the requested child process directly, without a shell in the
  middle. On Linux, the runner marks itself non-dumpable immediately before
  `exec`.
- `run` and `up` replace any value a child prints with `****`, which keeps
  values out of terminals, screen recordings, and logs by accident. It does
  not stop a program that leaks a value on purpose; see
  [Output redaction](docs/redaction.md).
- The dashboard listens only on loopback, exposes metadata rather than values,
  and uses one-time session material, Host/Origin checks, CSRF protection, and
  no-store headers.
- `export` is intentionally different: it writes plaintext. EnvRune names the
  variables, warns before writing, asks for `YES`, and asks again for a
  destination inside a Git worktree.

Security is also operational. Do not paste values into terminals, issue
trackers, or configuration files; do not treat an exported dotenv file as a
safe long-term copy. Read the [security model](docs/security.md) before using
EnvRune for sensitive credentials.

## Building from source

EnvRune currently builds with Go 1.27.

```sh
go test ./...
go build -trimpath -o bin/envrune ./cmd/envrune
./bin/envrune --help
```

The [build guide](docs/building.md) describes the expected toolchain, local
verification, and the distinction between a source build and a release asset.

## Releases

Prebuilt binaries for Linux, macOS, and Windows (amd64 and arm64) are
published on the [releases page](https://github.com/YagoLagrottiBracco/envrune/releases).
Releases are built by GitHub Actions whenever a `v*` tag is pushed:

```sh
git tag v0.1.0
git push origin v0.1.0
```

Treat `main` as active development.

## License

EnvRune is available under the [Apache License 2.0](LICENSE).
