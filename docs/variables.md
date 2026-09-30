# Documented variables and `envrune setup`

A `variables:` section in `envrune.yml` says what each variable is for, how a
new developer gets a value, and what a valid value looks like. It never holds
a value. EnvRune uses it in three places:

- `envrune setup` walks a new developer through every variable;
- `run`, named commands, `up`, `env`, and `export` refuse to start with a
  value that does not fit, and say which variable and which rule;
- `envrune types` generates typed settings for TypeScript and Python.

```yaml
version: 1
project: shop
default_env: development

variables:
  DATABASE_URL:
    description: Postgres database for the API
    how_to_get: Run `make db` for a local one, or ask in #infra for staging
    type: url
    format: ^postgres(ql)?://
  STRIPE_KEY:
    description: Stripe secret key
    how_to_get: Stripe dashboard → Developers → API keys (use test mode)
    format: ^sk_test_
  PORT:
    type: int
    required: false

environments:
  development:
    DATABASE_URL: shop.database-url.development
    STRIPE_KEY: shop.stripe-key.development
```

| Key | Meaning |
| --- | --- |
| `description` | What the variable is for. |
| `how_to_get` | Where a developer gets a value. |
| `type` | `string` (the default), `url` (with a scheme and a host), `int`, or `bool` (`true`, `false`, `1`, `0`, `yes`, `no`). |
| `format` | A regular expression ([Go syntax](https://pkg.go.dev/regexp/syntax)) the value must match. Anchor it with `^` and `$` to match the whole value. |
| `required` | `true` by default. A required variable must be linked in every environment a command runs with. |

A variable can also be listed with no keys (`FEATURE_FLAG:`) just to make it
required.

## `envrune setup`

```text
$ envrune setup
[INFO] Setting up 3 variables for development.

DATABASE_URL
  Postgres database for the API
  How to get it: Run `make db` for a local one, or ask in #infra for staging
  Expected: a URL, matching ^postgres(ql)?://
Reference [shop.database-url.development]:
DATABASE_URL: ********
Confirm DATABASE_URL: ********
[OK] DATABASE_URL is ready (shop.database-url.development).
...
[OK] 2 of 3 variables are ready for development.
```

For each variable, `setup` checks whether it is already linked with a valid
value. If not, it explains it, proposes a reference (press Enter to accept),
asks for the value twice without echoing it, checks it, stores it, and links
it in `envrune.yml`. When the reference you choose is already stored with a
valid value, it offers to link that value instead. Optional variables are
asked about first and can be skipped. Use `--env staging` for another
environment. Running `setup` again only asks about what is still missing.

## Checks before a command starts

```text
$ envrune run -- npm start
[ERROR] Environment "development": DATABASE_URL (shop.database-url.development) is not a URL with a scheme and a host; STRIPE_KEY is required but not linked in development. Run `envrune setup` to fix it, or see variables: in envrune.yml.
```

Messages name the variable, its reference, and the rule, never the value.
Variables that `envrune.yml` links but `variables:` does not document are
not checked.

## Typed settings: `envrune types`

`envrune types` turns `variables:` into code, so editors complete the names
and a typo fails before runtime. It reads only `envrune.yml`, needs no unlock,
and never writes a value.

```sh
envrune types                   # env.d.ts next to envrune.yml (TypeScript)
envrune types python            # settings.py: a pydantic-settings class
envrune types --output src/env.d.ts
envrune types python --output -   # print instead of writing
```

TypeScript gets declarations for `process.env`. Every value in the
environment is a string, so each variable is typed `string`, optional when
`required: false`, with its description, type, and format in a comment:

```ts
declare namespace NodeJS {
  interface ProcessEnv {
    /** Postgres database for the API. Type: url. Format: ^postgres(ql)?:// */
    readonly DATABASE_URL: string;
    readonly PORT?: string;
  }
}
```

Python gets a [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
class that parses and checks the values when you create it: `url` becomes
`AnyUrl`, `int` and `bool` become `int` and `bool`, and `format` becomes a
`pattern` on string variables.

```python
from settings import Settings

settings = Settings()          # fails early if a value does not fit
print(settings.DATABASE_URL.host)
```

Variables that an environment links without documenting them are added as
optional strings, with a note. `types` does not replace a file it did not
generate unless you pass `--force`. Commit the generated file, and run
`envrune types` again after changing `variables:`.
