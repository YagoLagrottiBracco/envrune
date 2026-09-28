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
| **Runtime** | Direct process launch | Inject an environment into one child process with `envrune run`. |
| **Session** | One password prompt | Use `envrune shell` to unlock once for a foreground working session. |
| **Overview** | Local dashboard | Inspect references and project bindings without exposing values in the browser. |

## Get started

### 1. Build the CLI

For now, build from a source checkout with Go 1.27:

```sh
go build -trimpath -o bin/envrune ./cmd/envrune
```

Run it from the repository root. Before managing another project, place the
binary on your `PATH` or use the absolute path to this `bin/envrune` file. The
examples below use `envrune` so they work from the project directory.

If your Go binary directory is already on `PATH`, Go can install the command
for you instead:

```sh
go install ./cmd/envrune
envrune --help
```

### 2. Create your vault

Run EnvRune with no command and follow the secure terminal prompts:

```sh
envrune
```

It asks for explicit confirmation before creating a vault, then asks you to
set and confirm a master password. That password is not stored and cannot be
recovered.

### 3. Bind a project

Create an `envrune.yml` at the root of a project. It contains only metadata:

```yaml
version: 1
project: example-service
environments: {}
```

Then open an EnvRune session from that project directory:

```sh
envrune shell
```

Inside the session, store a value (it is entered through a hidden prompt),
bind it to an environment variable, and run your application:

```text
envrune [unlocked] > set service.development
envrune [unlocked] > link SERVICE_TOKEN service.development --env development
envrune [unlocked] > run --env development -- ./your-application
```

Use `lock` or `exit` when you are done. See the complete walkthrough in
[Getting started](docs/getting-started.md).

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
| `envrune shell` | Open one foreground session and enter the master password once. |
| `set <reference>` | Store or replace a value through a hidden terminal prompt. |
| `list` / `usage <reference>` | Review references and where they are bound. |
| `link <VAR> <reference> --env <environment>` | Add a binding to the nearest `envrune.yml`. |
| `generate <reference> --length <n>` | Generate and store a secret. |
| `import <file.env>` | Import dotenv entries after an interactive confirmation. |
| `run --env <environment> -- <command>` | Start one direct child process with resolved variables. |
| `export --env <environment> [--output path] [--force]` | Deliberately create a plaintext dotenv file after confirmation. |
| `ui [--port <port>] [--no-browser]` | Start the metadata-only local dashboard. |

Commands may be run individually, but each one asks for the master password.
Use `envrune shell` for normal multi-step work. Set `NO_COLOR=1` for plain
terminal output; redirected output is already plain.

## Documentation

| Guide | Read it when you want to… |
| --- | --- |
| [Getting started](docs/getting-started.md) | Build EnvRune, create a vault, and connect a first project. |
| [Advanced usage](docs/advanced-usage.md) | Work with environments, imports, exports, generated values, and sessions. |
| [Local dashboard](docs/local-ui.md) | Understand the loopback UI, its token flow, and its limits. |
| [Security model](docs/security.md) | Review encryption, process handling, threat boundaries, and operating guidance. |
| [Building from source](docs/building.md) | Run checks and produce a local CLI binary. |

## Security at a glance

- The vault uses Argon2id for password derivation and XChaCha20-Poly1305 for
  authenticated encryption.
- The master password is never persisted. Shell sessions retain unlocked state
  only in the foreground process, then clear it when locked or exited.
- `run` launches the requested child process directly, without a shell in the
  middle. On Linux, the runner marks itself non-dumpable immediately before
  `exec`.
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

**Status: source pre-release.** This checkout has no tagged binary release.
Build from the checked-out source and treat `main` as active development.

## License

EnvRune is available under the [Apache License 2.0](LICENSE).
