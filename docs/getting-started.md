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
go install ./cmd/envrune
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

The master password is not saved. If it is forgotten, the existing vault
cannot be recovered. Use a password manager for the password itself; do not
put it in a shell script, dotenv file, or project configuration.

You can explicitly initialize a vault with `envrune init`; the no-argument
onboarding path is recommended because it requires an explicit creation
choice.

## Create a project mapping

At a project root, create a file called `envrune.yml`:

```yaml
version: 1
project: example-service
environments: {}
```

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

`set` opens a hidden prompt for the value. It is not echoed and should not be
pasted into this guide, a commit, or terminal output. `link` changes only
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

## What to read next

- Use [advanced usage](advanced-usage.md) for imports, generated values,
  exports, and multiple environments.
- Read the [local dashboard guide](local-ui.md) before starting `envrune ui`.
- Read the [security model](security.md) to understand EnvRune's guarantees
  and boundaries.
