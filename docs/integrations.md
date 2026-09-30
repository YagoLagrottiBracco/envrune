# Integrations

Editors, containers, and terminals usually start processes on their own, so
there is no terminal in which to type the master password. Run
`envrune unlock` (or `envrune keychain enable`) first; every example below
then works without a prompt.

## VS Code

The [EnvRune extension](../packages/vscode) adds a status bar item that shows
whether the vault is unlocked, an EnvRune view with each project's
environments, variables, and commands, warnings on `process.env.X` and
`os.environ["X"]` reads that `envrune.yml` does not link, and debugging with
the vault through one line in `launch.json`:

```jsonc
{ "type": "node", "request": "launch", "program": "${workspaceFolder}/src/server.js", "envrune": true }
```

It is not on the Marketplace yet; see its README to install it from a
checkout. Without it, the tasks and launch configurations below run programs
through `envrune run`. Ready-to-copy files are in
[`examples/vscode`](../examples/vscode).

### Tasks

`tasks.json` runs commands through EnvRune:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "dev (envrune)",
      "type": "shell",
      "command": "envrune",
      "args": ["run", "--", "npm", "run", "dev"],
      "isBackground": true,
      "problemMatcher": []
    },
    {
      "label": "all services (envrune up)",
      "type": "shell",
      "command": "envrune",
      "args": ["up"],
      "isBackground": true,
      "problemMatcher": []
    }
  ]
}
```

### Debugging Node.js

The Node.js debugger accepts a wrapper executable. VS Code appends the inspect
flag and the program after `runtimeArgs`, so EnvRune starts Node with the
variables and the debugger attaches as usual:

```json
{
  "name": "Debug with envrune",
  "type": "node",
  "request": "launch",
  "runtimeExecutable": "envrune",
  "runtimeArgs": ["run", "--", "node"],
  "program": "${workspaceFolder}/src/index.js",
  "console": "integratedTerminal"
}
```

For `npm` scripts, use `"runtimeArgs": ["run", "--", "npm", "run", "dev"]`
and drop `program`.

### Debugging Python, Go, and others

When a debugger cannot use a wrapper, start the program under the debug
server with EnvRune and attach to it. For Python with `debugpy`:

```json
// tasks.json
{
  "label": "debugpy (envrune)",
  "type": "shell",
  "command": "envrune",
  "args": ["run", "--", "python", "-m", "debugpy", "--listen", "5678", "--wait-for-client", "main.py"],
  "isBackground": true,
  "problemMatcher": { "pattern": { "regexp": "^$" }, "background": { "activesBegin": ".", "endsPattern": "." } }
}
```

```json
// launch.json
{
  "name": "Attach (envrune)",
  "type": "debugpy",
  "request": "attach",
  "connect": { "host": "127.0.0.1", "port": 5678 },
  "preLaunchTask": "debugpy (envrune)"
}
```

Go works the same way with `dlv debug --headless --listen=:2345` and an
`attach` configuration with `"mode": "remote"`.

Avoid `envFile` in `launch.json`: it needs a plaintext `.env` file.

## Docker Compose

Let Compose read the variables from the environment that EnvRune creates, so
no value is written into `compose.yaml`:

```yaml
# compose.yaml
services:
  api:
    image: ghcr.io/acme/api:latest
    environment:
      - DATABASE_URL          # passed through from the environment
      - STRIPE_KEY
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?run through envrune}
```

```sh
envrune run -- docker compose up
envrune run --env staging -- docker compose up -d
```

A bare name such as `- DATABASE_URL` copies the value from the environment
into the container. `${NAME}` interpolates it into the file at start time;
`${NAME:?message}` fails fast when EnvRune was not used. Both work, but keep in
mind that values handed to a container are visible to `docker inspect` and
`docker compose config`, as with any other Compose setup.

As a named command:

```yaml
commands:
  stack: docker compose up
```

## Terminal hook (like direnv)

The hook loads a project's variables into your shell when you `cd` into it
and removes them when you leave. Every command you start there then sees
them, without `envrune run`.

```sh
# bash: ~/.bashrc
eval "$(envrune hook bash)"
# zsh: ~/.zshrc
eval "$(envrune hook zsh)"
# fish: ~/.config/fish/config.fish
envrune hook fish | source
```

```powershell
# PowerShell: $PROFILE
Invoke-Expression ((envrune hook powershell) -join "`n")
```

The hook never asks for a password. It loads nothing while the vault is
locked, and picks the variables up at the next prompt after `envrune unlock`.
It uses `default_env`.

This is a trade-off: `envrune run` gives variables to one process, while the
hook gives them to your whole shell and to everything you start from it until
you leave the directory. Use it on machines and for projects where that is
acceptable.

`envrune env` is what the hook uses; you can also call it directly:

```sh
eval "$(envrune env --env staging)"
```

It refuses to print to a terminal, where the values would appear on screen.
