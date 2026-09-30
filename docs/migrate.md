# Moving from .env files: `envrune migrate`

`envrune migrate` moves the `.env` files of a project into the vault and
links every variable in `envrune.yml`. It shows the whole plan first, without
values, and writes nothing until you confirm.

```sh
cd my-app
envrune migrate               # this folder
envrune migrate --siblings    # this folder and the folders next to it
envrune migrate --env local   # use another name for the default environment
```

## What it reads

| File | Environment |
| --- | --- |
| `.env`, `.env.local` | the default environment (`development`, or `--env`) |
| `.env.<name>`, `.env.<name>.local` | `<name>`, such as `production` or `test` |
| `.env.example`, `.sample`, `.template`, `.dist`, `.defaults` | left alone: these hold placeholders meant to be committed |

`.local` files override the others, as dotenv libraries do. The files may use
the syntax those libraries accept: `export`, spaces around `=`, single, double,
and backtick quotes, values that span lines, and `#` comments. `${VAR}` is
stored as written, not expanded. Empty values are skipped.

## The plan

```text
Migration plan (values are not shown):

  /code/shop/api (creates envrune.yml, project "api")
    .env → development: 2 variables
    .env.production → production: 1 variable
      DATABASE_URL                 development  → shared.database-url.development
      API_TOKEN                    development  → api.api-token.development
      API_TOKEN                    production   → api.api-token.production

  /code/shop/web (envrune.yml exists, project "storefront")
    .env.local → development: 2 variables
      DATABASE_URL                 development  → shared.database-url.development
      SESSION_SECRET               development  → web.session (skipped: the vault holds another value; it is kept)

  Vault: 3 new references, 0 already stored.
  .gitignore: .env and .env.* will be ignored in each folder.
  Left alone: /code/shop/api/.env.example (a template).

Apply this plan? [y/N]
```

- Each variable gets the reference `<project>.<variable>.<environment>`,
  unless `envrune.yml` already links it, or the vault already holds the same
  value under another reference, which is then reused.
- When projects use the same value, `migrate` asks whether to store it once
  under a `shared.` reference, so rotating it later updates every project.
- A reference that already holds a different value is never overwritten: the
  vault may be newer than the file. The variable is listed as skipped.
- `.gitignore` in each folder gets `.env`, `.env.*`, and `!.env.example`,
  unless they are already there.

After applying, `migrate` offers to delete the migrated files. If a file was
committed to Git, it warns you: its values are in the repository's history,
so run [`envrune scan`](guard.md) and rotate them.

Then run your commands through EnvRune:

```sh
envrune run -- npm run dev
```
