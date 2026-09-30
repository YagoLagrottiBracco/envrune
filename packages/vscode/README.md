# EnvRune for VS Code

See, run, and debug with the secrets in your [EnvRune](https://github.com/YagoLagrottiBracco/envrune)
vault, without `.env` files. The extension never shows or stores a value: it
asks the `envrune` CLI for names and states, and hands values only to the
debug sessions you start.

## Features

- **Status bar:** 🔓 with the time left while the vault is unlocked, 🔒 when
  it is locked. Click it to unlock for 8 hours (in a terminal, where the
  password is asked) or to lock now.
- **EnvRune view** in the Explorer: each `envrune.yml` in the workspace, its
  environments, and each variable with its reference and whether the vault
  has it; the commands under `commands:`, with a button to run each one.
- **Debug with EnvRune:** add `"envrune": true` (or `{ "env": "staging" }`)
  to any configuration in `launch.json`. The variables are added to that
  session's environment in memory; values set under `env` in `launch.json`
  win. The vault must be unlocked, since the debugger cannot ask for a
  password.

  ```jsonc
  {
    "type": "node",
    "request": "launch",
    "name": "API",
    "program": "${workspaceFolder}/src/server.js",
    "envrune": true
  }
  ```

- **Unlinked variables:** a warning on `process.env.X`, `import.meta.env.X`,
  `os.environ["X"]`, `os.environ.get("X")`, and `os.getenv("X")` when no
  environment in `envrune.yml` links `X`, with a quick fix that links it.
  System variables such as `NODE_ENV` and `PATH` are left alone; add others
  to `envrune.diagnostics.ignore`.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `envrune.path` | `envrune` | The executable, when it is not on `PATH`. |
| `envrune.diagnostics.enabled` | `true` | Warn about unlinked variables. |
| `envrune.diagnostics.ignore` | `[]` | Names not to warn about. |

## Requirements

EnvRune 0.2 or later on `PATH`. The extension is not yet on the Marketplace;
build it from a checkout with `npx @vscode/vsce package` in `packages/vscode`
and install the `.vsix` with **Extensions: Install from VSIX…**.
