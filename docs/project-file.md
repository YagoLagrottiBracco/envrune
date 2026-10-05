# More in envrune.yml

This describes what `envrune.yml` can hold beyond variables, commands, and
documented variables: environments that build on each other, a personal
override, workspaces, secrets delivered as files, templates, and checks.
Each is a top-level key of its own; a file without them means what it
always meant.

Like the rest of EnvRune, none of this knows a service. A secret is a
value, a file, or a line in a template; what it is for is the project's
business.

## Environments that build on each other

```yaml
environments:
  development:
    DATABASE_URL: shop.dev-database
    API_KEY: shop.dev-api-key
    LOG_LEVEL: shop.log-level
  staging:
    DATABASE_URL: shop.staging-database    # the rest comes from development

extends:
  staging: development
```

`extends` maps an environment to the one it builds on. The environment gets
every variable of its parent and replaces the ones it names itself. Chains
are allowed (`production: staging`); a cycle, or a parent that does not
exist, is an error that names both.

There is no way to remove an inherited variable. An environment that should
not have one does not extend the environment that does.

## A personal override

`envrune.local.yml`, next to `envrune.yml`, holds one developer's own
choices and is not committed:

```yaml
environments:
  development:
    DATABASE_URL: personal.my-own-database
```

It has one key, `environments`, with the same shape. Its variables replace
or add to the shared ones for that developer only. `envrune link --local`
writes it, and adds the file to `.gitignore` when it creates it; `doctor`
says so if Git tracks it.

It holds references, like `envrune.yml`, never values. It is kept out of
Git because it describes one person's setup, not because it is secret.

## A workspace of several packages

A repository with several packages keeps one `envrune.yml` at its root and
one in each package. A package names the root:

```yaml
# api/envrune.yml
version: 1
project: shop-api
workspace: ..
environments:
  development:
    PORT: shop.api-port
```

Each of the package's environments starts from the root's environment of
the same name, then applies the package's own `extends` and variables. An
environment only the root has is available to the package too. The package
also uses the root's `cloud:` link when it has none.

The root is one level up the chain: a root with a `workspace` of its own is
an error. Commands, `up`, and documented variables are not inherited; the
root already runs a package's commands with `project:`
([daily-workflow.md](daily-workflow.md)).

The order, from weakest to strongest: the workspace root, the parent
environments (`extends`), the environment's own variables, and the personal
override.

## Secrets delivered as files

Some programs want a path, not a value: a certificate, a service account
file, a private key.

```yaml
files:
  - SERVICE_ACCOUNT_FILE
  - TLS_CLIENT_KEY
```

For each variable listed, `run`, named commands, and `up` write the secret's
value to a file only the user can read, in a folder made for that command,
and give the program the file's path in the variable. The folder is in
memory where the system offers that (`/dev/shm` on Linux) and is removed
when the command ends, also when it is stopped.

`envrune set <reference> --file <path>` stores a file's content as a
secret, which the prompt cannot do for content with several lines.

What it does not do: a program that copies the file elsewhere, or a crash
of `envrune` itself, can leave a copy behind; and the content is on disk,
however briefly, on systems with no in-memory folder.

## Configuration files from templates

```yaml
render:
  APP_CONFIG: config/application.yml.tmpl
```

The template is a file in the project with `{{NAME}}` wherever a variable's
value belongs:

```yaml
datasource:
  url: {{DATABASE_URL}}
  password: {{DATABASE_PASSWORD}}
```

Before the command starts, the template is filled in with the environment's
values and written the same way as a file secret; `APP_CONFIG` receives the
path. A name the environment does not define is an error that names it,
never an empty string. `{{` that is not followed by a variable name and
`}}` is left as it is, so templates of other tools pass through.

`envrune render <template> [--env e] -- <command>` does the same for one
run, giving the path in `ENVRUNE_RENDERED`.

The template is committed and holds no value. The rendered file holds
values and never exists in the project folder.

## Where a service is

```yaml
forward:
  PAYMENTS_URL: https://api.example.com/v1
```

`PAYMENTS_URL` receives the address of the service, for the program to
build its requests on. Normally that is the address as written.

It matters with a [sensitive secret](managed-keys.md): a value the program
uses without receiving it, because its requests take a detour through a
proxy that `envrune` starts. Most programs take that detour by themselves,
from the standard proxy variables. One that ignores them cannot, but nearly
every program can be told where its service is. When a sensitive secret of
the environment allows the host in `forward`, the variable holds an address
on this computer instead (`http://127.0.0.1:<port>/v1`), and requests sent
there are forwarded to the service as the detour would.

The address must be `https`, on the standard port, with no user, query, or
fragment. A variable is either in `forward` or in an environment, not both.
`run`, named commands, `up`, `render`, `check`, and the MCP server set these
variables; `env` and `export` do not.

## Checks

```yaml
checks:
  payments: sh -c 'curl -fsS https://api.example.com/v1/me -H "Authorization: Bearer $API_KEY"'
  database: pg_isready -d "$DATABASE_URL"
```

A check is a command that succeeds when a secret still works. `envrune
check [name...] [--env e]` runs each one with the environment's variables,
with its output masked, and reports which passed, by exit status. EnvRune
does not know how to test a key of any service; the project says how.

`doctor` already reports secrets that are expired or old. Checks answer the
other question: whether a value is still accepted.

## Unused secrets

The vault notes, at most once a day per secret, the last day a command was
given it. `envrune doctor` lists the secrets no command used in 90 days and
that no project it knows links, as candidates to remove, and `envrune usage
<reference>` shows the day. Nothing is removed automatically.

The note is the day, kept in the vault next to the secret's other metadata.
