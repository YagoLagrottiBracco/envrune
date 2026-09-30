# AI agents: `envrune mcp`

`envrune mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server that lets an AI coding agent run your project's commands with their
secrets injected, without giving it a way to read the secrets. Configure it
in Claude Code, Cursor, or VS Code with GitHub Copilot, and the agent can
start the dev server, run the tests, or run a migration, while every vault
value in the output reaches it as `****`.

## Design

The server speaks MCP over standard input and output. It is started by the
agent's host, in the project folder, and offers these tools:

| Tool | What it returns |
| --- | --- |
| `list_environments` | Environment names and the default one. |
| `list_variables` | For one environment: variable names, their references, whether each is stored, and the documentation from `variables:`. |
| `list_commands` | The commands under `commands:` in `envrune.yml`. |
| `run_command` | Runs one of those commands and returns its exit code and output. |
| `doctor` | The findings of `envrune doctor`. |

No tool returns a value. Specifically:

- **Only named commands run.** `run_command` takes the name of a command
  from `commands:`, never a command line, and does not accept extra
  arguments. An agent that could run any command could run
  `curl -d "$STRIPE_KEY" https://…` or write a key to a file, and masking
  would not see it. `envrune mcp --allow-args` lets the agent append
  arguments to named commands, and `--allow-any-command` adds a
  `run_any_command` tool; both are off by default, and the server says so in
  its tool descriptions when they are on.
- **All output is masked.** The output of `run_command` is masked against
  every value in your vault and in the project's team file, not only the ones
  the command receives, as described in [Output redaction](redaction.md). It
  is truncated to the last 64 KiB.
- **It never asks for a password.** The agent's host has no terminal to ask
  in. The server unlocks through a running agent (`envrune unlock`), the
  system keychain, or `ENVRUNE_PASSWORD`/`ENVRUNE_PASSWORD_FILE`, and it
  checks again on every call: `envrune lock` stops the agent's access at
  once. While the vault is locked, tools answer with an error that tells the
  agent to ask you to unlock.
- **Commands are bounded.** Each run stops after `timeout_seconds` (120 by
  default, at most 600), together with every process it started.

## Setup

In every case, EnvRune must be on the `PATH` the host starts it with, and
the vault must be unlocked (`envrune unlock --ttl 8h`) before the agent uses
it.

**Claude Code**, for one project (this writes `.mcp.json`, which you can
commit):

```sh
claude mcp add --scope project envrune -- envrune mcp
```

**Cursor**, in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "envrune": { "command": "envrune", "args": ["mcp"] }
  }
}
```

**VS Code with GitHub Copilot**, in `.vscode/mcp.json`:

```json
{
  "servers": {
    "envrune": { "type": "stdio", "command": "envrune", "args": ["mcp"] }
  }
}
```

Then ask the agent to "run the tests with envrune" or "start the api with
envrune"; it will call `list_commands` and `run_command`.

## Keep the agent away from values

The MCP server is only safe if it is the agent's only way in. An agent that
can run shell commands as you can also run `envrune` itself: with the vault
unlocked, `envrune env` or `envrune copy` would hand it values. And it can
read files: a leftover `.env` holds values in plain text.

- **Delete `.env` files** once they are migrated (`envrune migrate` offers
  to), and keep `envrune scan` clean.
- **Deny the agent the `envrune` CLI and the dotenv files.** In Claude Code,
  add to `.claude/settings.json`:

  ```json
  {
    "permissions": {
      "deny": [
        "Bash(envrune:*)",
        "Read(./.env)",
        "Read(./.env.*)",
        "Read(~/.local/share/envrune/**)"
      ]
    }
  }
  ```

  In Cursor, list `.env` and `.env.*` in `.cursorignore`, and keep command
  approval on for the terminal. In GitHub Copilot, use content exclusion in
  the repository or organization settings, and review terminal commands
  before they run. Rules like these differ between tools and versions;
  check your tool's documentation.
- **Review what the agent runs.** Keep approvals on for terminal commands,
  so a command such as `printenv` inside a script is something you see.

## What this does not protect against

`envrune mcp` keeps values out of the agent's context by accident and by
default. It does not contain an agent that is trying to get them: a command
under `commands:` that the agent can edit (for example, a test file or a
`package.json` script) runs with the real values and can send them anywhere.
Treat editing code that runs with secrets, and approving its execution, with
the same care as handing over the values.
