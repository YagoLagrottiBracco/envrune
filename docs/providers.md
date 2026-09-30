# Pulling and pushing with services

`envrune pull` copies values from a hosting service or a secret manager into
the vault and links them in `envrune.yml`. `envrune push` copies the
variables of an environment to a service. Both work on one environment at a
time (`--env`, or the default one).

| Provider | `pull` | `push` | Needs |
| --- | --- | --- | --- |
| `vercel` | yes | yes | `VERCEL_TOKEN`, and a project linked with `vercel link` or `--project` |
| `1password` | yes | no | the 1Password CLI (`op`), signed in |
| `github` | no | yes | the GitHub CLI (`gh`), signed in |

Railway and AWS Secrets Manager are planned.

## Pull

```text
$ envrune pull vercel --env production
From Vercel production variables of the project linked in .vercel/project.json into production (values are not shown):
  DATABASE_URL                 → shop.database-url.production (changed)
  PUBLIC_URL                   → shop.public-url.production (new, will be linked)
[WARNING] STRIPE_KEY is a sensitive Vercel variable, which cannot be read back.
Store 2 values in the vault? [y/N]
```

For each variable, `pull` uses the reference `envrune.yml` already links, or
proposes `<project>.<variable>.<environment>` and links it. It shows whether
each value is new, changed, or unchanged, without showing values, and writes
nothing until you confirm. Replaced values stay in `envrune history`, so
`envrune rollback` undoes a pull. Variables linked to a `team.` reference are
not changed; update them with `envrune team set`.

### Vercel

```sh
export VERCEL_TOKEN=...          # https://vercel.com/account/tokens
envrune pull vercel              # environment development → Vercel development
envrune pull vercel --env staging --target preview
envrune push vercel --env production
```

EnvRune environments map to the Vercel environment of the same name
(`development`, `preview`, `production`); use `--target` for any other name.
The project comes from `.vercel/project.json`, which `vercel link` writes, or
from `--project <id or name>`. Variables of the type *sensitive* cannot be
read back from Vercel, so `pull` lists them instead. `push` creates or
updates encrypted variables for that one target.

### 1Password

```sh
envrune pull 1password --item "Payments API" --vault Engineering
```

Each field of the item with a value becomes a variable: the label
`Stripe key` becomes `STRIPE_KEY`. Notes are skipped. EnvRune does not push
to 1Password, because the `op` commands that write items take values as
command-line arguments, which other processes on the machine can read.

## Push

```text
$ envrune push github --env production --repo me/shop
API_KEY
DATABASE_URL
[WARNING] These 2 variables from production will be stored in GitHub Actions secrets of me/shop.
Type YES to confirm: ***
```

- `github`: `--repo owner/name` (the current repository by default) and
  `--github-env name` for an environment's secrets. Values go to `gh secret
  set` on its standard input.
- `vercel`: `--target` and `--project`, as for pull.

## How values travel

Values move only over the service's HTTPS API or through the standard input
and output of its official CLI: never as command-line arguments and never
through a file. EnvRune does not store service tokens; Vercel's comes from
`VERCEL_TOKEN`, and the CLIs keep their own sign-in.
