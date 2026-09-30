# Daily workflow

This guide covers the features that make EnvRune as quick to use as a `.env`
file: unlocking once per day, a default environment, named commands, several
services at once, and a few everyday helpers.

## Unlock once, not in every terminal

Each command needs the vault key. EnvRune finds it in this order:

1. `ENVRUNE_PASSWORD_FILE` or `ENVRUNE_PASSWORD`, for CI (see
   [Teams and CI](teams-and-ci.md));
2. a running **agent**, started by `envrune unlock`;
3. the **system keychain**, after `envrune keychain enable`;
4. the master password prompt.

### Agent with a time limit

```sh
envrune unlock --ttl 8h     # asks for the master password once
envrune run -- npm start    # in any terminal: no prompt
envrune lock                # forget the key before the 8 hours are up
```

Like `ssh-agent`, the agent is a small background process that holds the
vault's data key in memory and answers on a Unix socket next to the vault (a
named pipe on Windows), and only to processes of your own user. It exits
when the time limit ends or when you run
`envrune lock`. Inside `envrune shell`, `unlock` starts the agent from the
open session without asking again.

### System keychain

```sh
envrune keychain enable     # asks for the master password once
envrune keychain disable
```

The data key is stored in Windows Credential Manager, the macOS Keychain, or
the Secret Service on Linux (install `libsecret-tools` for `secret-tool`). Your
operating-system login then unlocks EnvRune. This is more convenient than the
agent, but the key stays available for as long as you are logged in. See
[Security model](security.md#agent-and-keychain) before choosing it.

`envrune status` shows which method is active.

## A default environment

Add `default_env` to `envrune.yml`, and every command that takes `--env` uses
it when you leave `--env` out:

```yaml
version: 1
project: shop
default_env: development
environments:
  development:
    DATABASE_URL: shop.database-url.development
  production:
    DATABASE_URL: shop.database-url.production
```

```sh
envrune run -- npm start                    # development
envrune run --env production -- npm start
```

A project with a single environment uses it without `default_env`.
`envrune project init` creates an `envrune.yml` with a `development`
environment as the default.

## Named commands

```yaml
commands:
  dev: npm run dev
  api:
    run: .venv/bin/python -m uvicorn main:app --port 8000
    dir: api            # relative to envrune.yml
    env: development    # optional; defaults to default_env
  test: go test ./...
```

```sh
envrune dev
envrune api --reload        # extra arguments are appended
envrune api --env staging   # override the environment
```

Commands are split into words the way a shell would split them, with quotes,
but no shell runs them. Pipes, `&&`, and `$VAR` expansion are not interpreted.
When you need them, say so explicitly: `sh -c "npm run build && npm start"`.
A built-in command, such as `list`, wins over a command with the same name;
`envrune doctor` warns about such clashes.

## Several services with one unlock: `envrune up`

```yaml
commands:
  api: .venv/bin/python -m uvicorn main:app --port 8000
  backend:
    run: npm run start:dev
    dir: backend
  web:
    run: npm run dev
    dir: web
up: [api, backend, web]
```

```sh
envrune up              # the services listed in up:, or every command
envrune up api web      # only these
```

Each service's output is prefixed with its name, in its own color:

```text
api     | INFO:     Uvicorn running on http://127.0.0.1:8000
backend | [Nest] 4120  - LOG [NestApplication] Nest application successfully started
web     |   ▲ Next.js 15.0.0 - Local: http://localhost:3000
```

Ctrl+C stops every service, including the processes they started (for
example, `npm` starting `node`). When one service exits, the others are
stopped too, as Procfile runners do.

### Services that keep their own envrune.yml

When each service already has its own `envrune.yml`, such as a monorepo
with `api/`, `backend/`, and `web/`, or sibling repositories, point a command
at that folder with `project:` instead of copying its links into one file:

```yaml
# envrune.yml at the root
version: 1
project: shop
environments: {}
commands:
  api:
    run: .venv/bin/python -m uvicorn main:app --port 8000
    project: api          # uses api/envrune.yml
  backend:
    run: npm run start:dev
    project: ../shop-backend
    env: staging          # an environment of ../shop-backend/envrune.yml
  web:
    run: npm run dev
    project: web
up: [api, backend, web]
```

A command with `project:` takes its links, `default_env`, and team file from
that folder's `envrune.yml`, and runs in that folder unless `dir:` says
otherwise. `envrune up` still asks for the master password once. `project:`
must be a relative path, so the file works on every machine, and
`envrune doctor` also checks each `envrune.yml` it points to.

## Values stay out of your terminal

`run`, named commands, and `up` replace any vault value a child prints with
`****`, including its URL-encoded and base64 forms:

```text
$ envrune run -- node -e "console.log(process.env.STRIPE_KEY)"
****
```

In a terminal, the child still runs in one, a pseudo-terminal that EnvRune
reads from, so colors, progress bars, and prompts work as before. Values
shorter than six characters, such as `3000` or `true`, are not masked;
`envrune doctor` lists them. Add `--no-redact` to connect the child straight
to your terminal:

```sh
envrune run --no-redact -- ./debug-config
envrune up --no-redact
```

Masking protects against accidents, such as a debug log in a screen
recording. A program that wants to leak a value can still do it, for example
by printing it reversed. [Output redaction](redaction.md) describes the
limits.

## Linking a reference that does not exist yet

```text
$ envrune link STRIPE_KEY stripe.test-key
[OK] Linked STRIPE_KEY to stripe.test-key for environment development.
stripe.test-key does not exist yet. Enter its value now? [y/N] y
Secret value:
Confirm secret value:
[OK] Secret stored: stripe.test-key
```

## Copying a value

```sh
envrune copy stripe.test-key                 # cleared after 30 seconds
envrune copy stripe.test-key --clear-after 10s
```

The clipboard is cleared only if it still holds that value, so something you
copied in the meantime is left alone. On Windows, the value is kept out of
clipboard history and cloud clipboard sync. On Linux, EnvRune uses `wl-copy`,
`xclip`, or `xsel`, and `clip.exe` inside WSL.

## Checking a project: `envrune doctor`

`doctor` reports, without printing any value:

- bindings whose reference does not exist, in every environment;
- `default_env`, `commands`, and `up` entries that point to nothing;
- `.env` files left in the project (and whether Git ignores them);
- lines in `envrune.yml` that look like a pasted secret value;
- a vault lock held by another process, and the unlock method in use;
- secrets that expired, expire within two weeks, or have not changed in 180
  days;
- a vault without a recovery key.

It exits with status 1 when it finds an error, so it can run in CI.

## Metadata, rotation, and history

```sh
envrune meta stripe.live-key --description "Stripe live secret" --owner payments --expires 2026-12-31
envrune list --long
envrune info stripe.live-key

envrune rotate session.signing-key          # new random value, same length
envrune rotate session.signing-key --length 64
envrune history session.signing-key
envrune rollback session.signing-key        # back to the previous value
```

Each secret keeps its five most recent earlier values, encrypted in the
vault. `rollback` swaps the current and previous values, so running it twice
undoes it. `rotate` lists the projects that use the secret so you know what
to restart. For values issued by a provider, such as an API key, rotate at
the provider and store the new value with `set`; the old one is kept the same
way.

## Recovery and backups

`envrune init` shows a **recovery key** once. Write it down and keep it
offline. If you forget the master password:

```sh
envrune recover             # asks for the recovery key, then a new password
```

Other commands:

```sh
envrune passwd              # change the master password
envrune recovery            # is a recovery key set?
envrune recovery reset      # create a new one; the old one stops working

envrune backup              # encrypted copy in <data dir>/envrune/backups
envrune backup ~/Dropbox/envrune-vault.ev1
envrune restore ~/Dropbox/envrune-vault.ev1              # checks the password first
envrune restore ~/Dropbox/envrune-vault.ev1 --recovery   # or the recovery key
```

A backup is the encrypted vault file itself. It opens with the master
password and recovery key that were valid when it was made. `restore` saves
the current vault next to it before replacing it.

Vaults created before recovery keys existed are upgraded automatically the
next time they are opened. Run `envrune recovery reset` once to give them a
recovery key.
