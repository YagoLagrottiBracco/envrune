# Getting started with EnvRune

This guide takes a new checkout from source build to a project that receives a
secret only when it runs. Examples use names, never secret values.

## Prerequisites

- Go 1.27 to build from source.
- An interactive terminal. EnvRune refuses to read master passwords and secret
  values from redirected input.
- A project directory where you can create `envrune.yml`.

Go is required for this source-build workflow. This checkout has no tagged
standalone binary release.

## Build and check the CLI

From the repository root:

```sh
go build -trimpath -o bin/envrune ./cmd/envrune
./bin/envrune --help
```

The help screen lists the available commands. Before working from another
project directory, put the binary on your `PATH` or use its absolute path. The
examples below use `envrune` to represent either of those choices.

If the Go binary directory is already on your `PATH`, this is an alternative
that installs the command through the Go toolchain:

```sh
go install github.com/YagoLagrottiBracco/envrune/cmd/envrune@latest
envrune --help
```

## Create an encrypted vault

Run the binary with no arguments:

```sh
envrune
```

EnvRune explains that it is uninitialized and asks whether it should create a
vault. Choose `y`, then enter and confirm a master password through the hidden
prompt.

The master password is not saved. EnvRune shows a recovery key once, right
after creating the vault. Write it down and keep it offline: with it,
`envrune recover` sets a new password. Without the password and the recovery
key, the vault cannot be opened. Use a password manager for the password
itself; do not put it in a shell script, dotenv file, or project
configuration.

You can explicitly initialize a vault with `envrune init`; the no-argument
onboarding path is recommended because it requires an explicit creation
choice.

## Create a project mapping

At a project root, run `envrune project init`, or create a file called
`envrune.yml` yourself:

```yaml
version: 1
project: example-service
default_env: development
environments:
  development: {}
```

With `default_env`, commands that accept `--env` use `development` when you
leave it out.

This file is safe to version because it has no values. EnvRune searches upward
from the current directory for the nearest `envrune.yml`, so run project-aware
commands from the project root or one of its subdirectories.

## Work in a session

Open the interactive shell from that project directory:

```sh
envrune shell

Enter the master password once. At the `envrune [unlocked] >` prompt, use this
sequence:

```text
set service.development
link SERVICE_TOKEN service.development --env development
run --env development -- ./your-application
```

`set` opens a hidden prompt for the value and asks for it twice. It is not
echoed and should not be pasted into this guide, a commit, or terminal output.
If a paste contains more than one line, Envrune discards all of it instead of
storing the first line and running the rest as commands. `link` changes only
`envrune.yml`; it associates the `SERVICE_TOKEN` variable with the named vault
reference. `run` resolves that binding and starts the application directly.

Your configuration will now resemble:

```yaml
version: 1
project: example-service
environments:
  development:
    SERVICE_TOKEN: service.development
```

Lock the session as soon as you finish:

```text
lock
```

`exit` does the same thing. Closing the terminal also ends the foreground
session.

## Unlock once for the day

To use EnvRune from several terminals, an editor, or `envrune up` without a
prompt each time:

```sh
envrune unlock --ttl 8h
envrune run -- ./your-application
envrune lock
```

## What to read next

- Use the [daily workflow](daily-workflow.md) for named commands, `up`,
  `copy`, `doctor`, rotation, and recovery.
- Use [advanced usage](advanced-usage.md) for imports, generated values,
  exports, and multiple environments.
- Use [integrations](integrations.md) for VS Code, Docker Compose, and the
  terminal hook.
- Read the [local dashboard guide](local-ui.md) before starting `envrune ui`.
- Read the [security model](security.md) to understand EnvRune's guarantees
  and boundaries.
