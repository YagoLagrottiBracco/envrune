# Advanced usage

EnvRune has two ways to work: individual commands, and `envrune shell`, which
unlocks once for a foreground interactive session. Individual commands prompt
for the master password unless the vault is unlocked by the agent
(`envrune unlock`) or the system keychain; see
[Daily workflow](daily-workflow.md). Every command works in both places.

`--env` is optional wherever it appears below when `envrune.yml` sets
`default_env` or defines a single environment.

## References and environments

A reference is a name for one encrypted value. A project variable binding is
separate metadata stored in `envrune.yml`.

```text
vault reference:  payments.production
project variable: PAYMENT_GATEWAY_TOKEN
environment:      production
```

From an unlocked shell, create the relationship:

```text
set payments.production
link PAYMENT_GATEWAY_TOKEN payments.production --env production
```

Use `list` to view references and `usage payments.production` to see their
project, environment, and variable bindings. Neither command prints a value.

## Run one process with an environment

Run an application from a directory at or below its `envrune.yml`:

```sh
envrune run --env production -- ./server
```

The `--` separator is required. EnvRune resolves the requested environment and
executes the named child process directly; it does not insert an intermediate
shell. Within `envrune shell`, omit the `envrune` prefix:

```text
run --env production -- ./server
```

The variables are supplied to that child process. They do not become an
exported, permanent part of the parent terminal session.

## Generate a value

Generate and store a new value under a reference:

```text
generate webhook.production --length 48
```

Use a reference that communicates ownership and environment. Do not put the
generated value in a ticket or a configuration file.

## Import a dotenv file

Import is useful while moving an existing project away from a local dotenv
file:

```text
import .env
```

EnvRune prints the entry names and requires a `YES` confirmation before it
writes them to the vault. Review the source file first; importing means the
plaintext file still exists until you securely remove it through your normal
workflow.

## Export only when a consumer requires a file

`run` is preferred because it does not create a plaintext dotenv file. Use
`export` only for a tool that truly requires one:

```sh
envrune export --env production --output /chosen/path/.env.production
```

Without `--output`, the default destination is `.env.<environment>` in the
current directory. EnvRune lists the variable names, warns that the result is
plaintext, and requires `YES`. If the destination is inside a Git worktree, it
requires another confirmation. Existing files require `--force`.

Treat the result as short-lived sensitive material. Do not commit it, attach
it to an issue, or leave it in a shared directory.

## Open the local dashboard

```sh
envrune ui
envrune ui --port 43821
envrune ui --no-browser
```

The dashboard is for inspection, not value editing. It shows references,
projects, environment bindings, and missing references, but it never returns
secret values to the browser. Full behavior and browser-session safeguards are
documented in [Local dashboard](local-ui.md).

## Sessions, locks, and output

`envrune shell` itself starts no background process. The unlocked vault
exists only in the foreground CLI process. Use `lock` or `exit` to close it
deliberately. `unlock` inside the shell starts the optional agent, which keeps
the key for other terminals until its time limit.

The vault file is locked only for the instant a process reads or writes it,
never for a whole session. You can keep several shells open and run several
projects at once. Each read picks up changes that other sessions have
committed. Each write is applied on top of the latest version on disk, so one
session never overwrites another session's secrets. If another process holds
the lock for more than a few seconds, the command reports its PID instead of a
password error.

`run` looks the command up on `PATH`, so `run --env development -- npm start`
works without an absolute path. When the command is missing or exits with a
non-zero code, Envrune says so and returns the same exit code.

EnvRune uses colored status output for an interactive terminal. Set
`NO_COLOR=1` to disable color. Redirected output is plain so that escape
sequences do not contaminate pipes or files.
