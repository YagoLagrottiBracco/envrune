# Why EnvRune

A `.env` file is the easiest way to give a program its secrets, and the
easiest way to leak them: it sits in plain text next to your code, gets
copied between projects, shows up in screenshots and logs, and is the first
file an AI coding agent reads. EnvRune keeps the same workflow (a name for
each variable, a value per environment) and moves the values into an
encrypted vault that only hands them to the processes you start.

## Migrate in two minutes

```sh
# 1. Install and create the vault (asks for a master password once).
brew install --cask yagolagrottibracco/tap/envrune   # or winget install YagoLagrottiBracco.EnvRune
envrune init                    # prints a recovery key: store it somewhere safe

# 2. Move the .env files of this project, or of the folders next to it, into the vault.
cd ~/code/shop
envrune migrate --siblings      # shows the plan without values, asks, then writes envrune.yml

# 3. Run things through EnvRune. Unlock once for the day.
envrune unlock --ttl 8h
envrune run -- npm run dev
```

`migrate` stores every value, links each variable in `envrune.yml` (which you
commit; it holds only names), offers one shared reference when projects use
the same value, adds `.env` to `.gitignore`, and offers to delete the files.
[Moving from .env files](migrate.md) has the details.

## What changes day to day

- **Nothing to copy.** A new developer clones the repository, runs
  `envrune setup`, and is asked for each variable with its description and
  how to get it.
- **Values stay out of sight.** `envrune run` and `envrune up` print `****`
  where a value would appear in the output; `envrune guard` blocks a commit
  that contains one; `envrune scan` finds old leaks in files and Git history.
- **AI agents can work without the values.** `envrune mcp` lets Claude Code,
  Cursor, or Copilot run your commands with the secrets injected and the
  output masked, through tools that never return a value.
- **One unlock, many terminals.** `envrune unlock --ttl 8h`, or the system
  keychain, and every command, editor, and debug session works.

## An honest comparison

As of September 2026, from each tool's documentation. Tools change quickly;
check them before you decide.

| | EnvRune | dotenv | 1Password CLI | Doppler | Infisical |
| --- | --- | --- | --- | --- | --- |
| Where values live | Encrypted vault on your machine | Plain-text file in the project | 1Password vaults | Doppler's cloud | Infisical Cloud, or your own server |
| Works offline, without an account | Yes | Yes | No: needs a 1Password account | No; an encrypted snapshot covers outages [^doppler-fallback] | No: needs Infisical Cloud or a self-hosted server |
| Runs a command with the secrets | `envrune run` | Loaded by the program | `op run` | `doppler run` | `infisical run` |
| Masks values in the output | Yes, by default | No [^dotenvx] | Yes, by default [^op-run] | Not documented | Not documented |
| Blocks commits that contain secrets | Yes: compares with your actual values | No | No | No | Yes: pattern-based scanning of 140+ secret types [^infisical-scan] |
| AI agents | MCP server whose tools never return values | — | MCP integrations and SDKs that retrieve credentials | MCP server, experimental [^doppler-mcp] | MCP server with tools that read secret values [^infisical-mcp] |
| Sharing with a team | Team file encrypted to each member's key, committed with the code | Copying files | Shared vaults, access control, audit | Projects, access control, audit | Projects, access control, audit |
| Self-hosting | Nothing to host | Nothing to host | No | No | Yes |
| Open source | Yes (Apache-2.0) | Yes | No | CLI only | Yes |

[^doppler-fallback]: [Doppler: secret fallback files](https://docs.doppler.com/docs/automatic-fallbacks).
[^dotenvx]: [dotenvx](https://dotenvx.com/docs/cli/run-redact/), a successor to dotenv, can redact values with `run --redact`.
[^op-run]: [1Password CLI: `op run`](https://www.1password.dev/cli/reference/commands/run) conceals secrets on stdout and stderr unless `--no-masking` is given.
[^infisical-scan]: [Infisical: secret scanning](https://infisical.com/docs/cli/scanning-overview).
[^doppler-mcp]: Doppler's MCP server is described by Doppler as experimental.
[^infisical-mcp]: [Infisical: Model Context Protocol](https://infisical.com/docs/ai/model-context-protocol.md).

The two approaches to leak detection complement each other: pattern-based
scanners, such as Infisical's or GitHub's push protection, recognize the
shape of known key formats, including keys you never stored anywhere;
EnvRune recognizes your actual values, including ones with no recognizable
format, such as a database password.

## When to choose something else

- **You need central administration today.** EnvRune has no server yet:
  there is no web console to grant and revoke access, no audit log of who
  read what, and no single sign-on. Doppler, Infisical, and 1Password have
  all of these. EnvRune Cloud is planned.
- **Your secrets already live in 1Password.** `op run` gives you injection
  and masking on top of vaults your company already manages; `envrune pull
  1password` can still bring items into a project that uses EnvRune.
- **Your production runtime needs the secrets.** EnvRune is built for
  development machines and CI. Servers and containers in production are
  better served by the platform's secret store or a secrets manager.

## What EnvRune does not protect against

Masking, `guard`, and the MCP server prevent accidents. A program you run
with secrets, or code an agent can edit and run, can still send them
anywhere, and any process running as you can read another's environment.
[The security model](security.md) lists what each protection covers and
what it does not.
