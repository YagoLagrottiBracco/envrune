# Keys managed by their owner: design

Status: **proposal, for review. Nothing here is implemented.** It builds on
EnvRune Cloud ([cloud-crypto.md](cloud-crypto.md)) and describes Phase 5 of
the roadmap: the owner of a key replaces it in one place, the team picks up
the new value without doing anything, and people who only need to use a key
do so without seeing it.

The decisions that are the owner's to make are collected under
[Decisions to approve](#decisions-to-approve).

## What exists today

- A new value written with `envrune cloud set` reaches a member's device the
  next time that device pulls. Nothing tells the device to pull, and a
  running process keeps the old value until someone restarts it.
- The `consumer` role keeps values off the screen: masked output, and no
  `copy`, `export`, `env`, or `push`. A consumer still holds the environment
  key, so the limit stops accidents, not extraction.
- The server records every fetch of an environment in the audit log. It
  does not know when a value is used.

## Goals

1. **One place to rotate.** `envrune cloud set` (or `--generate`) is the
   whole rotation: every device and every running process moves to the new
   value on its own, and the owner sees who has.
2. **Three levels of "use without seeing"**, each stated with what it does
   and does not protect:

   | Level | The value | Protects against |
   | --- | --- | --- |
   | 1. Consumer role (exists) | reaches the developer's machine, never the screen | accidents: logs, screenshots, pasting |
   | 2. Injection proxy | never reaches the developer's machine | extraction by the developer |
   | 3. Temporary credentials | is never the master key; what reaches the machine expires | extraction, and a leak after the developer left |

3. **Zero-knowledge stays the default.** Levels 2 and 3 need the server to
   hold a credential it can use. That is a deliberate exception, chosen per
   secret by an owner, and visible everywhere the secret is listed.

Non-goals: protecting a value from the upstream service or from a server
the owner chose to trust with it; hiding which secrets exist.

## 1. Rotation that distributes itself

### Learning that a value changed

Devices **poll**. A new route returns, for the environments a device asks
about, only the epoch and the version number of each secret: no ciphertext,
so it costs one small query and is not a fetch in the audit log.

```text
GET /api/v1/versions?env=<id>&env=<id>   →  { "<env id>": { "epoch": 3, "secrets": { "stripe-key": 7 } } }
```

- `envrune run`, `up`, and named commands ask before starting, with a short
  timeout (1.5 s). If anything is newer than the device's copy, they pull
  it, verify it as today, and start with the new values. Offline, or on a
  timeout, they start with the copy they have, as today.
- A process started with `--restart-on-rotate` (and every service of `up`
  that asks for it) keeps asking every 30 seconds while it runs.

Why not push or server-sent events: the CLI talks only to the EnvRune Cloud
API, which on Vercel runs as short-lived functions that cannot hold a
connection open for hours, and a self-hosted server would need a second
code path. Polling metadata is one route that works the same everywhere. A
value reaches a running process within 30 seconds instead of at once, which
is enough for a rotation; it is not an emergency stop, which is
`member remove` and revocation.

### What a running process does

- By default: `envrune` prints one line to its own standard error, not the
  child's, saying which variables have a new value and that the command
  must be restarted to use them. It never restarts something the developer
  did not ask it to.
- With `--restart-on-rotate`: it stops the child as `up` already does
  (SIGTERM, then SIGKILL after a grace period; the process group on Unix,
  the job on Windows), resolves again, and starts it again. Three failed
  restarts in a row stop the loop and report the failure.

### Transition period

Rotating a key at a provider usually leaves the old key valid for a while.
`envrune cloud set <path> --transition 24h` records, with the new version,
until when the previous one is still expected to work. During that time a
device that has not synced is **behind**, and after it **stale**:

- `envrune doctor` and `run` warn about a stale copy before starting;
- the panel and `envrune cloud rotation` show, per secret, which devices and
  tokens have fetched the environment since the new version was written and
  which have not.

The transition is information for people, signed with the version like its
other fields. EnvRune does not keep the old key working at the provider and
does not stop a device from using a stale copy: only the provider can
invalidate a key.

"Who uses the new version" is derived from the audit log: a device or token
uses version N once it fetched the environment after N was written. No new
table. It shows that the new ciphertext reached the device, which is the
most the server can know.

## 2. Consumers: recording use

The server sees fetches, not use: a consumer can run commands for weeks from
one fetch. To record use, the CLI reports it:

- when `run`, `up`, or `mcp` injects a value that is restricted to use
  (consumer role), the CLI records the secret, the environment, and the time
  in the vault, and sends the records to the server the next time it is
  online (`secret.use` in the audit log, marked as reported by the device).
- It records names and times. It does not record the command line, which
  may contain data the organization should not collect.

This is **the device's own account**: a consumer who modifies the CLI can
skip it. The documentation says so. It answers "which secrets does this team
actually use, and when", not "prove that this person did not use it".

## 3. Injection proxy

For an HTTP API key marked `proxied`, the developer's program never receives
the key. It receives a URL and a short-lived token:

```text
program ──▶ https://cloud.example.com/proxy/…  (Authorization: Bearer <grant>)
                │  checks the grant, replaces the header with the real key
                ▼
            https://api.stripe.com/…           (Authorization: Bearer sk_live_…)
```

### Where the proxy runs

Two modes were considered.

- **Local** (the `envrune` process on the developer's machine holds the key
  and forwards requests): the key is still on the machine, in a process the
  developer controls. It keeps the key out of the program's environment and
  logs, which the consumer role and masking already do. It does not reach
  level 2, so it is **not proposed**.
- **Cloud** (the EnvRune Cloud server holds the key and forwards requests):
  the key never reaches the developer. This is the proposal.

### What it costs: the server can read a proxied secret

A proxied secret is encrypted to the **proxy identity**, an age key pair
whose private half is configuration of the server
(`ENVRUNE_PROXY_IDENTITY`). The server decrypts the value in memory for each
request. Therefore, for proxied secrets only:

- a compromised server, or whoever runs it, can read the value;
- a copy of the database alone still cannot: the proxy identity is not in
  the database.

Everything else stays as in [cloud-crypto.md](cloud-crypto.md). To make the
exception hard to create by accident:

- only an owner or admin marks a secret `proxied`, with
  `envrune cloud set <path> --proxied --upstream https://api.stripe.com`;
- the CLI shows the proxy identity's fingerprint and what marking the secret
  means, and asks for confirmation; the device pins the fingerprint, so a
  server cannot swap in another identity later;
- the panel, `cloud org show`, and `cloud pull` mark proxied secrets, and
  the audit log records the marking;
- a proxied secret is **write-only for people**: no member's device receives
  a key that decrypts it, whatever their role. Rotating it is setting a new
  value. It is stored apart from the environment's other secrets, which stay
  encrypted under the environment key the server never has.

### Grants

`envrune run` asks the server for a grant when a variable resolves to a
proxied secret: a random token bound to the user, the device, the secret,
and an expiry (1 hour by default). A running program cannot be handed a new
token, so while the command runs `envrune` extends the same grant's expiry;
it lapses within the hour after the command ends. The
variable receives the grant instead of the key, and a second variable
receives the proxy's address:

```yaml
environments:
  development:
    STRIPE_SECRET_KEY: cloud.stripe-key          # proxied: receives a grant
    STRIPE_API_BASE: cloud.stripe-key.proxy      # receives https://cloud.example.com/proxy/…
```

The server stores a hash of each grant. A grant stops working when it
expires, when its device is revoked, and when its user is removed or loses
the scope. Asking for a grant, and the number of requests it served, go to
the audit log.

### What the proxy forwards

- Only to the **upstream** recorded with the secret, which the admin's
  device signs together with the value. A request cannot name another host,
  so a grant cannot be used to send the key somewhere else.
- It replaces the `Authorization` header and forwards method, path, query,
  body, and the other headers; it removes hop-by-hop headers and cookies.
  It does not follow redirects from the upstream, which could point
  elsewhere with the key attached.
- It streams bodies in both directions and limits size and duration.
- It never logs bodies or the key. It logs the grant, the method, the path
  without its query, the status, and the time.

First targets: **Stripe** (its libraries accept another API address) and
**any API that takes `Authorization: Bearer`**. APIs that sign requests with
the key (AWS Signature V4) or put it in the URL are out of scope for the
proxy; AWS is covered by level 3.

### What it does not do

A developer with a grant can call the upstream with the key's full power
while the grant is valid: the proxy hides the key, it does not narrow what
the key may do. Narrowing is level 3, or a restricted key at the provider.

## 4. Temporary credentials

Instead of the master credential, `envrune run` receives a credential made
for that developer, limited in scope and time:

| Provider | The server holds | It issues |
| --- | --- | --- |
| AWS | a role it may assume | STS credentials for that role, with a session policy and a duration (15 min to 12 h) |
| PostgreSQL, MySQL | an admin connection string | a database user with a random password, the grants of a template role, and an expiry |
| Stripe | a secret key | a restricted key with the permissions the owner chose, if Stripe's API allows creating one for the account; otherwise this provider is left out and the proxy is the answer for Stripe |

The master credential is stored like a proxied secret: encrypted to the
proxy identity, write-only for people, marked everywhere. The same exception
to zero-knowledge applies, and the same confirmation.

Providers implement one interface, so more can be added:

```go
type Issuer interface {
    // Issue creates a credential for one user and returns the variables to
    // inject and how to take it back.
    Issue(ctx context.Context, master []byte, request Request) (Credential, error)
    // Revoke takes back a credential that Issue returned, if the provider
    // can; it is called at expiry and when the user loses access.
    Revoke(ctx context.Context, master []byte, credential Credential) error
}
```

- **Expiry and revocation.** The server records what it issued. A scheduled
  job revokes what expired; removing a member or revoking a device revokes
  what they hold at once. STS credentials cannot be revoked one by one: they
  expire, and for a removed member the role gets a policy denying sessions
  issued before that moment.
- **What reaches the machine** is a real credential, so the consumer limits
  apply to it (masked, not shown). If it leaks, it is limited and it
  expires.
- **Where issuing runs.** On the server, for the same reason as the proxy:
  the developer's machine must not hold the master credential. Database
  providers need the server to reach the database, which a database inside
  a private network does not allow from Vercel; a self-hosted server inside
  that network does.

## What a compromised server can do, after this phase

| Secrets | A compromised server can |
| --- | --- |
| Ordinary (the default) | what [cloud-crypto.md](cloud-crypto.md) says: read names and activity, refuse service; not read a value |
| Proxied | also read the value, and call the upstream with it |
| Masters of temporary credentials | also read the master, and issue credentials for itself |

It still cannot make a secret proxied by itself: marking is a signed write
from an admin's device, and devices pin the proxy identity.

## Decisions to approve

1. **The proxy runs on the server, and proxied secrets are readable by the
   server.** This is the only way the key stays off the developer's machine.
   The alternative is to not build level 2. Proposal: build it, per secret,
   with the confirmation and the marking described above.
2. **No local proxy mode.** It would not add protection over the consumer
   role. Proposal: leave it out.
3. **Polling, not push.** Proposal: metadata polling, 30 seconds while a
   process runs with `--restart-on-rotate`, once before each start
   otherwise.
4. **Use is reported by the device.** Proposal: yes, names and times only,
   documented as the device's own account.
5. **The proxy identity is one key per server**, set by whoever runs it.
   Rotating it means setting every proxied secret again. Proposal: accept
   that for now; per-organization identities can come later.
6. **Order and scope.** Proposal: (a) rotation that distributes itself and
   the record of use, which need no exception to zero-knowledge; (b) the
   proxy, for Stripe and Bearer APIs; (c) temporary credentials, starting
   with AWS STS and PostgreSQL, then MySQL, and Stripe only if its API
   allows it. Each is released on its own.
7. **The sentence** "the developer uses the key without needing to see it;
   and, for critical keys, without being able to see it" goes into the
   documentation only after (b) and (c) exist, as the roadmap says.
