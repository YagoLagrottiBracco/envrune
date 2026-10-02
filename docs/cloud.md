# EnvRune Cloud

EnvRune Cloud shares secrets between the members of a team and with CI,
end-to-end encrypted: values are encrypted and decrypted by the `envrune`
CLI on your devices, and the server stores only ciphertext and names. How
that works, and what a compromised server can and cannot do, is in
[cloud-crypto.md](cloud-crypto.md).

The local vault keeps working as before, offline and without an account.
The cloud is optional, and a project can mix local, team, and cloud secrets.

There is no hosted EnvRune Cloud yet. Run the server yourself, as
[self-hosting.md](self-hosting.md) describes, and use its address where this
guide says `https://cloud.example.com`.

## Sign in and set up your keys

```sh
envrune login --server https://cloud.example.com   # or set ENVRUNE_CLOUD_SERVER
envrune cloud init
```

`login` opens the browser to sign in and hands the session to the CLI. It
is stored in your vault, encrypted like your secrets.

On your first device, `cloud init` creates your account keys and shows a
**recovery key once**. Write it down and keep it offline: with it,
`envrune cloud recover` restores your access if you lose every device.

On another device, `cloud init` registers it as pending and shows a
fingerprint. Approve it from a device you already use:

```sh
envrune cloud device approve <id>   # check that both screens show the same fingerprint
```

Then run `envrune cloud init` on the new device again to finish.
`envrune cloud whoami` shows your account and device fingerprints.

## Organizations, projects, and members

```sh
envrune cloud org create acme
envrune cloud project create acme shop
envrune cloud env create acme/shop/production
envrune cloud member add acme alice@example.com --role maintainer --scope shop/*
```

Before `member add` signs anything, it shows the fingerprint the server
gave for that person's account. Ask them to run `envrune cloud whoami` and
compare over another channel, such as a call. A different fingerprint means
the key is not theirs; do not add it.

`member add` ends by printing an invitation for the new member:

```sh
envrune cloud org join acme --fingerprint K7QD-2MXA-P9FE-…
```

Send it over that same channel, not through the server. It makes the new
member's device trust the organization only if it is the one you created:
the fingerprint covers the organization and its root keys. A member who
skips it trusts what the server shows first; `envrune cloud org show` tells
them so and shows the fingerprint to compare.

### Root holders

Your account key is the organization's **root**: every membership traces
back to it. If you lose every device and your recovery key, nobody can add
owners or admins again. To avoid depending on one person, name up to two
more root holders **when creating the organization**:

```sh
envrune cloud org create acme --roots bob@example.com,carol@example.com
```

Each must have run `envrune cloud init`, and you confirm each one's
fingerprint as for a member. A root holder is an owner who can never be
removed or changed, and the set cannot change later, so choose people who
will stay.

Roles:

| Role | Can |
| --- | --- |
| owner | everything |
| admin | manage members, projects, environments, tokens; read and write values |
| maintainer | read and write values in their scope |
| consumer | run programs with the values; not see, copy, or export them |
| auditor | see names, versions, and the audit log; no values |

A scope is a list of `project/environment`, `project/*`, or `*`.

Removing a member (`envrune cloud member remove acme <user-id>`) starts a new
key for every environment they could use, so they cannot read anything
written afterwards. **They may still know the values they already read**:
replace those values, as described next.

Removing a member, or changing their role with `member set` so that they
can no longer write somewhere, also signs again what they had signed: the
values they wrote, the keys they shared, and the memberships they issued.
Devices refuse a former member's signature, so the command does this for
you and says what it did. Two things it may leave to someone else, and
names when it does:

- an environment the member could write to that **you** do not administer.
  Someone who does runs `envrune cloud rotate acme/shop/staging
  --accept-removed`; until then its values do not verify;
- a member they had added with a role you may not grant. An owner adds them
  again with `envrune cloud member set`.

Machine tokens a removed member created are revoked, since they have seen
them. Create new ones for CI.

## After someone leaves: guided rotation

When a member is removed or a machine token revoked, the server lists every
secret they fetched. The list is in the panel and in the CLI:

```sh
envrune cloud rotation acme          # what is still waiting; --all shows everything
```

Each secret waits until one of these happens:

```sh
envrune cloud set acme/shop/production/payments-key              # the new value from the provider
envrune cloud set acme/shop/production/session-key --generate  # a random value, for ones you make up
envrune cloud rotation accept acme/shop/production/sentry-dsn  # it stays as it is, on the record
```

Writing a new value marks the secret rotated. A new key
(`envrune cloud rotate`, which `member remove` runs for you) does **not**:
it encrypts the same value again, and whoever left still knows it.
`rotation accept`, and "Keep this value" in the panel, are for owners and
admins, and are written to the audit log.

The list comes from the server's record of fetches. It shows that ciphertext
left the server, not what someone did with it.

## Secrets

```sh
envrune cloud set acme/shop/production/payments-key   # asked twice, never echoed
envrune cloud set acme/shop/production/session-key --generate   # a random value, never shown
envrune cloud pull acme/shop/production             # or: envrune cloud sync
envrune cloud copy acme/shop/production/payments-key
```

`pull` and `sync` download ciphertext, verify every signature, and keep an
encrypted copy in your vault, so commands keep working offline with the last
synced state. You rarely need to run them: `run`, named commands, and `up`
ask the server whether anything changed before they start, and pull what
did. A command that is already running says when a value it uses was
replaced, and `envrune run --restart-on-rotate` restarts it with the new
value by itself. A server that serves an older version than one you have seen
is refused (`--allow-older` accepts it).

## Replacing a value

```sh
envrune cloud set acme/shop/production/payments-key --transition 24h
envrune cloud status acme/shop/production
```

`cloud set` is the whole rotation. Every device pulls the new value the next
time it runs a command while online, and a running command says so or
restarts by itself (`--restart-on-rotate`). `--transition` records how long
the previous value keeps working where it was issued, for your own
planning.

`cloud status` lists the devices and machine tokens that fetched the
environment, when each last synced, and which are still **behind** on a
value, or **stale** once its transition has passed. It shows what reached
each device, not whether a process there was restarted. Those who
administer the environment, and auditors, can see it.

## Audit log

The server records every fetch, write, rotation, membership change, device
approval, and token use: who, from which device or token, and when. Owners,
admins, and auditors read it in the panel, or export it:

```sh
envrune cloud audit export acme --output audit-2026-10.jsonl
envrune cloud audit verify audit-2026-10.jsonl                    # offline, no vault needed
envrune cloud audit verify audit-2026-11.jsonl --since audit-2026-10.jsonl
```

The export is one JSON object per line. `export` and `verify` compute the
hash chain again, so an entry that was edited, removed, or inserted is
found. Your device also remembers the last entry it verified, and refuses a
later export that no longer holds it; `--since` does the same between two
files. Export regularly and keep the files where the server cannot change
them: that is what makes rewriting the log detectable.

### Limiting offline use

By default a device keeps working with its last synced copy for as long as
it stays offline. An owner or admin can limit that:

```sh
envrune cloud org set acme --offline-days 30   # or: off
```

After 30 days without syncing an environment, commands that need it stop
and ask for `envrune cloud pull`. A removed member's device cannot pull, so
it stops working by itself. This limits how long a forgotten or kept laptop
stays useful; it does not take back values someone already saw, and it does
not stop someone who changes their clock.

## Use cloud secrets in envrune.yml

Link the project to a cloud project with `cloud:`, then reference secrets
with `cloud.`:

```yaml
version: 1
project: shop
cloud: acme/shop
environments:
  production:
    DATABASE_URL: cloud.database-url                    # acme/shop/production/database-url
    SENTRY_DSN: cloud.acme.shared.production.sentry-dsn # any cloud secret, in full
    LOCAL_ONLY: personal.local-only                     # the local vault, as before
```

- `cloud.<name>` is a secret of the linked project, in the environment of
  the same name as the one being run.
- `cloud.<org>.<project>.<environment>.<name>` names any secret you can use.
  Environments whose names contain `.` or `_` can only be used with the short
  form.
- References that start with `cloud.` go to the cloud **only when envrune.yml
  has `cloud:`**, so a file from before EnvRune Cloud that uses local
  `cloud.*` references keeps working unchanged.

`run`, `up`, named commands, `doctor`, `guard`, and `scan` read cloud values
from the synced copy. If an environment is not on this device yet, the error
says which one to pull.

### Consumers

A consumer's values reach programs but not the screen: `run` and `up` always
mask them in output (`--no-redact` is refused), and `export`, `env`, `copy`,
and `push` refuse to show them, and `envrune mcp --allow-any-command` refuses
to run an agent's own command line with them. **This prevents accidents, not a determined
consumer**: whoever runs a program with a value can read it on their own
machine, for example by printing it from the program.

## Moving from a team file

A project that shares secrets through `envrune.team.json`
([teams-and-ci.md](teams-and-ci.md)) can move them to a cloud environment:

```sh
envrune cloud import-team acme/shop/production            # shows what goes where, then asks
envrune cloud import-team acme/shop/production --relink   # and points envrune.yml at the cloud
```

Each team reference becomes a cloud secret of the same name, with dots
turned into dashes (`team.payments.key` becomes `payments-key`). Running it again
stores only what changed. `--relink` rewrites the variables of `envrune.yml`
that read those references, adds `cloud: acme/shop` if the file has no link,
and keeps your comments.

Then make everyone who needs the values a member of the organization, and
delete the team file. **Deleting it takes nothing back**: whoever was a
member of the team file can still read what it held, from the Git history
too. Replace any value that should not stay known.

## CI and deploys

Create a machine token for the environments a pipeline needs:

```sh
envrune cloud token create acme --scope shop/production --name deploy --expires 90d
```

The token is shown once. Store it as a CI secret named `ENVRUNE_TOKEN`, and
point the CLI at the server:

```yaml
# .github/workflows/deploy.yml
- name: Deploy
  env:
    ENVRUNE_TOKEN: ${{ secrets.ENVRUNE_TOKEN }}
    ENVRUNE_CLOUD_SERVER: https://cloud.example.com
  run: envrune run --env production -- ./deploy.sh
```

With `ENVRUNE_TOKEN` set, `cloud.` references resolve from the server
through the token, with no vault and no password. The token carries the
organization's root keys, so the job verifies who shared the key and who
wrote each value without trusting the server. Its scope limits what it can
read; `envrune cloud token revoke <id>` ends it.

## Limits

- The server sees names of organizations, projects, environments, and
  secrets, who is a member, and when values were fetched. It never sees a
  value or a key that decrypts one.
- It can refuse service or hide recent changes from a device that has not
  seen them yet.
- It maps `org/project/environment` to an environment without a signature,
  so it could serve a different environment of the same organization that you
  or a token may also read; it cannot serve one outside your scope or forge a
  value.
