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
Never paste it into a chat, an issue, or a file that is synced: if someone
else may have seen it, replace it with `envrune cloud recovery reset`.

On another device, `cloud init` registers it as pending and shows a
fingerprint. Approve it from a device you already use:

```sh
envrune cloud device approve <id>   # check that both screens show the same fingerprint
```

Then run `envrune cloud init` on the new device again to finish.
`envrune cloud whoami` shows your account and device fingerprints.

`envrune cloud doctor` checks, in order, what has to hold for all of this
to work: the server answers and its database is set up, your session is
valid, this device is trusted, your recovery key's recipient on the server
is yours, and each organization's membership verifies. Run it first when
something does not work.

If a command fails and the message does not say why, run it with
`--verbose` right after `envrune`, or with `ENVRUNE_VERBOSE=1`:

```sh
envrune --verbose cloud init
```

It prints each request to the server and its answer's status, never a
header, a body, or a value. An answer of 500 or more is the server's
problem; whoever runs it finds the cause in the server's log.

## Organizations, projects, and members

[first-team.md](first-team.md) walks two people through this section and
the next ones, step by step.

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

## Sensitive secrets: use without receiving

A consumer cannot see a value, but their machine receives it. For a key that
must not reach someone's machine at all, an owner or admin marks it
**sensitive** and says which hosts it may be sent to:

```sh
envrune cloud set acme/shop/production/payments-key --sensitive --allow-host api.example.com
```

In `envrune.yml` it is referenced like any other cloud secret
(`PAYMENTS_KEY: cloud.payments-key`). When a member runs the project,

```sh
envrune run -- npm start
```

the program gets a placeholder (`envrune_sealed_…`) instead of the value,
and its HTTPS requests to `api.example.com` go through the EnvRune Cloud
server, which puts the real value where the placeholder is: in a header, in
Basic credentials, in the address, or in a JSON or form body. Requests to
other hosts are not touched. It works the same for any service; EnvRune
does not know what the key is for.

What to know before using it:

- **The server can read a sensitive secret.** It is the one exception to
  the server never seeing a value, which is why it is chosen per secret and
  why `cloud set --sensitive` shows the server's proxy identity and asks
  first. The server needs `ENVRUNE_PROXY_IDENTITY`
  ([self-hosting.md](self-hosting.md)).
- **Nobody reads it back**, you included. To replace it, set it again.
- **It hides the value; it does not limit what the value can do.** Someone
  with access can make any request the service accepts. `envrune cloud
  audit export` shows who used it, toward which host, and when
  (`secret.forward`).
- **It needs the server for every request**, so it does not work offline.
- **The program must honour the standard proxy variables**
  (`HTTPS_PROXY`), as most HTTP libraries do; Node reads them because
  `envrune` sets `NODE_USE_ENV_PROXY`. A program that ignores them sends the
  placeholder, which the service refuses.
- **Only for values that travel in an HTTPS request.** A database password,
  or a key the program signs with itself, stays an ordinary secret.
- **A client certificate can be one too**, for services that identify
  callers by certificate: `--client-cert client.pem --client-key client.key`
  next to `--sensitive --allow-host`. The server presents it to those hosts.
- A name is one kind of secret: a secret that members have already read
  cannot be turned into a sensitive one. Use a new name, and a new value.

The design, and what a compromised server could do with sensitive secrets,
is in [managed-keys.md](managed-keys.md).

## Rules about who may fetch

Scopes say what each member may use. Rules say what a role may never fetch,
whoever grants what:

```yaml
# envrune.policy.yml
rules:
  - environments: "*/production"
    deny: [consumer]
  - environments: "shop/production"
    deny: [admin, maintainer, consumer]   # people never fetch it; machine tokens do
```

```sh
envrune cloud policy set acme envrune.policy.yml   # owners only
envrune cloud policy show acme
envrune cloud policy clear acme
```

The server refuses a denied role the environment's values, its keys, and
the use of its sensitive secrets. Rules never apply to owners, who keep the
environment manageable, or to machine tokens, which have their own scopes.

## Access for a limited time

A member who needs an environment for a while asks for it:

```sh
envrune cloud access request acme/shop/production --for 4h --reason "incident 214"
```

An owner or admin sees the request in the panel and in `envrune cloud access
list acme`, and decides with the CLI, since approving signs the member's
scope:

```sh
envrune cloud access approve acme <request>    # or: deny
```

When the time is up, **the server refuses the member by itself**: nobody
has to remember. To finish, an administrator runs

```sh
envrune cloud access end acme <request>
```

which signs the scope back, starts new keys for the environments the member
loses, and lists the values they fetched meanwhile to replace. It also ends
access early. Until then the member's device may still hold a copy from
before the time ran out; [an offline limit](#limiting-offline-use) bounds
that.

## Being told what happens

```sh
envrune cloud webhook set acme https://hooks.example.com/envrune   # owners and admins
envrune cloud webhook show acme
envrune cloud webhook clear acme
```

The server posts each event to that address as JSON: the action, its
target, who did it, and when. Events are the audit log's entries without
the frequent ones (fetches, reported use, forwarded requests), so they
never hold a value. `webhook set` prints a secret once; every request
carries `X-EnvRune-Signature: sha256=<HMAC-SHA256 of the body, in hex>`,
which the receiver checks before trusting an event.

An event is tried up to eight times, and `webhook show` says when
deliveries are failing. EnvRune knows no chat or mail service: point the
webhook at whatever your team already uses to route notifications.

## When something goes wrong

**A device is lost or stolen.** Revoke it from another device, or from the
panel under "Your devices":

```sh
envrune cloud device list
envrune cloud device revoke <id>
```

The server stops serving it at once. The command starts a new key for the
environments that device held one for, and `envrune cloud rotation acme`
lists the values it had fetched, which whoever has it may know.

**Someone may have seen your recovery key.** Replace it from a device you
already use:

```sh
envrune cloud recovery reset
```

It shows a new recovery key once; the old one stops opening anything on the
server. Your devices keep working, and nobody else has to do anything. If a
copy of the server's database from before may also be in the wrong hands,
that is not enough: see
[Replacing the recovery key](cloud-crypto.md#replacing-the-recovery-key).

**A project may be compromised**, and you do not know how far:

```sh
envrune cloud emergency acme/shop
```

Only an owner can, after typing the project's name. Every machine token
that reaches the project is revoked, and every device but yours loses its
keys for it, so nothing written from now on can be read by anyone else.
Every value of the project is listed to replace. Nobody is removed: review
the members, then give the keys back with `envrune cloud share acme` and
create new tokens for CI.

What each of these does at once on the server, and what your CLI finishes,
is in [cloud-operations.md](cloud-operations.md).

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

Each command a consumer runs with cloud values is noted on their device,
with the names of the secrets and the time, and reported to the audit log
(`secret.use`) the next time the device is online. It tells you what the
team uses and when. It is the device's own account, so it is not proof that
a value was not used.

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
