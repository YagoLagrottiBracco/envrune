# Keys managed by their owner: design

Status: **direction approved; being implemented in the order under
[Order](#order).** It builds on EnvRune Cloud
([cloud-crypto.md](cloud-crypto.md)): the owner of a key replaces it in one
place, the team picks up the new value without doing anything, and people
who only need to use a key do so without seeing it.

One rule shapes all of it: **EnvRune knows no service.** Nothing here is
built for a particular provider or API. A secret is a secret; what the owner
chooses is how far it may travel.

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
2. **Two levels of "use without seeing"**, each stated with what it does
   and does not protect:

   | Level | The value | Protects against |
   | --- | --- | --- |
   | Consumer role (exists) | reaches the developer's machine, never the screen | accidents: logs, screenshots, pasting |
   | Sensitive secret | never reaches the developer's machine | extraction by the developer |

3. **Zero-knowledge stays the default.** A sensitive secret needs the server
   to hold a value it can use. That is a deliberate exception, chosen per
   secret by an owner, and visible everywhere the secret is listed.

Before either level, the simplest protection is not to hand out the key at
all: give people who do not need production a scope that covers only the
development environment, with test credentials there. Scopes already do
this. A sensitive secret is for someone who must run against the real thing.

Non-goals: protecting a value from the service it is sent to, or from a
server the owner chose to trust with it; hiding which secrets exist.

## 1. Rotation that distributes itself

### Learning that a value changed

Devices **poll**. A new route returns, for the environments a device asks
about, only the epoch and the version number of each secret: no ciphertext,
so it costs one small query and is not a fetch in the audit log.

```text
GET /api/v1/versions?env=<id>&env=<id>   →  { "<env id>": { "epoch": 3, "secrets": { "payments-key": 7 } } }
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
- With `--restart-on-rotate`: it stops the child and everything the child
  started, as `up` already does, resolves again, and starts it again. If it
  cannot be started again, `envrune` reports that and exits.

Both look at every value the command was started with, wherever it comes
from: a value replaced in the local vault or in the team file is noticed
the same way as one replaced in the cloud.

### Transition period

Rotating a key at a provider usually leaves the old key valid for a while.
`envrune cloud set <path> --transition 24h` records until when the previous
value is still expected to work. A device or token that has not fetched the
environment since the new value was written is **behind**, and once the
transition has passed, **stale**. `envrune cloud status <env>` lists every
device and token that fetched the environment with its last sync and that
state, and the panel shows how many are behind.

A device cannot tell by itself that its copy is behind: online, it has
already pulled the new value before starting a command; offline, it cannot
ask. So this is a view for the owner, not a warning on the device.

The transition is information for people and is not signed: a server that
lied about it would only mislabel a device. EnvRune does not keep the old
value working where it was issued and does not stop a device from using a
copy that is behind: only whoever issued the value can invalidate it.

"Who uses the new version" is derived from the audit log: a device or token
uses version N once it fetched the environment after N was written. No new
table. It shows that the new ciphertext reached the device, which is the
most the server can know.

## 2. Consumers: recording use

The server sees fetches, not use: a consumer can run commands for weeks from
one fetch. To record use, the CLI reports it:

- when `run`, a named command, `up`, or `mcp` injects a value that is
  restricted to use (consumer role), the CLI notes the secrets, the
  environment, and the time in the vault, and sends the notes to the server
  the next time it is online (`secret.use` in the audit log, marked as
  reported by the device). A device that stays offline keeps the last 500.
- It records names and times. It does not record the command line, which
  may contain data the organization should not collect.

This is **the device's own account**: a consumer who modifies the CLI can
skip it. The documentation says so. It answers "which secrets does this team
actually use, and when", not "prove that this person did not use it".

## 3. Sensitive secrets

### Why encryption alone cannot do this

For a program to use a value, the value must be readable where the program
runs. Whoever controls that machine can read what the program reads, however
the value arrived and however briefly it is decrypted. So "use without being
able to see" has one shape: the value stays somewhere else, and something
there uses it on the program's behalf.

### How it works

The owner marks a secret sensitive and says which hosts it may be sent to:

```sh
envrune cloud set acme/shop/production/payments-key --sensitive --allow-host api.example.com
```

From then on, a developer's program receives a **placeholder** in place of
the value, such as `envrune_sealed_x7k2…`, and its requests to the allowed
hosts take a detour:

```text
program ── request with the placeholder ──▶ envrune (same machine)
                                                │  forwards it, as this member
                                                ▼
                                       EnvRune Cloud server
                                                │  puts the real value where the
                                                │  placeholder is; only for an allowed host
                                                ▼
                                          api.example.com
```

The server does not know what the secret is for. It replaces one piece of
text with another wherever it appears in the request:

- in header values, including inside `Authorization: Basic`, which it
  decodes, replaces, and encodes again;
- in the URL's query;
- in the body, when it is text (JSON, form data) within a size limit.

In the response it does the reverse, so a service that echoes the value
back shows the program the placeholder again.

A sensitive secret may also be a **client certificate** with its private
key, for services that identify their callers that way:

```sh
envrune cloud set acme/shop/production/bank-certificate --sensitive \
  --allow-host api.example.com --client-cert client.pem --client-key client.key
```

It is sealed like a value and the server presents it to the allowed hosts.
The program's placeholder for it carries nothing; a variable that
references the secret is what sends the program's requests to those hosts
through the server. A request can present one certificate, and can carry
other sensitive values next to it.

That is the whole mechanism, and it is the same for every secret. It covers
any service where the secret travels in an HTTPS request, which is how API
keys, tokens, and client credentials are used.

### How the program's requests reach envrune

`envrune run` starts a small proxy on the loopback interface for the
lifetime of the command and points the program at it with the standard
variables (`HTTPS_PROXY`, `HTTP_PROXY`). Requests to hosts that no sensitive
secret allows pass straight through, untouched and unread. Requests to an
allowed host are read so they can be forwarded.

Reading an HTTPS request means ending the program's TLS connection at
envrune. For that, each run creates a certificate authority that exists
only in memory and only for that run, and tells the program to trust it
through the variables runtimes read for extra authorities
(`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`). Nothing is installed on the machine. What envrune sees
this way is what the program sent: the placeholder, never the value.

On a network that only lets traffic out through its own proxy, `envrune`
uses it: requests that do not take the detour leave through the proxy the
program would have used (`HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` as
`envrune` itself was started with), with its user and password if the
address has them, and so does `envrune`'s own connection to the server.

One limit follows. A program that ignores those variables cannot be
redirected this way, and its requests would carry the placeholder to the
service, which refuses it: nothing leaks, but nothing works.

`run`, named commands, `up`, `render`, `check`, and the MCP server set this
up. Commands that would show a value (`env`, `export`, `copy`) refuse an
environment's sensitive secrets, saying why; `doctor` counts them as
present.

### What it costs: the server can read a sensitive secret

A sensitive secret is encrypted to the **proxy identity**, an age key pair
whose private half is configuration of the server
(`ENVRUNE_PROXY_IDENTITY`). The server decrypts the value in memory for each
request. Therefore, for sensitive secrets only:

- a compromised server, or whoever runs it, can read the value;
- a copy of the database alone still cannot: the proxy identity is not in
  the database.

Everything else stays as in [cloud-crypto.md](cloud-crypto.md). To make the
exception hard to create by accident:

- only an owner or admin marks a secret sensitive;
- the CLI shows the proxy identity's fingerprint and what marking the secret
  means, and asks for confirmation; the device pins the fingerprint, so a
  server cannot swap in another identity later;
- the panel, `cloud org show`, and `cloud pull` mark sensitive secrets, and
  the audit log records the marking;
- a sensitive secret is **write-only for people**: no member's device
  receives a key that decrypts it, whatever their role. Rotating it is
  setting a new value. It is stored apart from the environment's other
  secrets, which stay encrypted under the environment key the server never
  has;
- the allowed hosts are signed by the admin's device together with the
  value, so the server cannot add a host of its own.

### Limits the server enforces

- **Only allowed hosts, only HTTPS.** A request naming another host is
  refused, so the detour cannot be used to send the value elsewhere. The
  server does not follow redirects, which could point elsewhere with the
  value attached.
- **Only members who may use the environment**, from an approved device.
  The program holds no credential for the server: `envrune` forwards each
  request with the member's own session, and the server checks the
  membership, the scope, and the device on every request. Removing a member
  or revoking a device stops their use at the next request.
- **Sizes and durations** are limited. A server on a platform that limits
  request size or time inherits that limit; a self-hosted one sets its own.
- **Use is recorded** per member, device, secret, and host, counted by the
  hour, with the first request of each hour in the audit log
  (`secret.forward`). No request body and no value is stored. The owner can
  see who used a secret, from where, toward which host, and how much.

### What it does not do

- **It hides the value; it does not narrow what the value can do.** A
  member with access can make any request the service accepts while the
  access lasts. If the service offers restricted or test credentials, use
  them for people who do not need full power.
- **It covers requests over HTTPS.** A secret that never travels in a
  request cannot be hidden this way: a database password sent over the
  database's own protocol, or a key the program uses itself to sign or
  encrypt. Such secrets stay ordinary ones, with the consumer role's
  limits.
- **It is for people, not for production.** A deployed service gets its
  values through a machine token, directly, with no detour.

## What a compromised server can do, after this

| Secrets | A compromised server can |
| --- | --- |
| Ordinary (the default) | what [cloud-crypto.md](cloud-crypto.md) says: read names and activity, refuse service; not read a value |
| Sensitive | also read the value, and send requests with it |

It still cannot make a secret sensitive by itself, or widen where one may
be sent: both are signed writes from an admin's device, and devices pin the
proxy identity.

## Order

1. **Rotation that distributes itself**, and the record of use. These need
   no exception to zero-knowledge.
2. **Sensitive secrets**: marking and storage, the server's forwarding, and
   the loopback proxy in `run`, then client certificates. Networks that
   require their own proxy come after.

Decided along the way:

- Devices poll for new versions; no push. One route works the same on a
  hosted and a self-hosted server.
- Use is reported by the device, names and times only, and documented as
  the device's own account.
- The detour runs on the server. A proxy holding the value on the
  developer's own machine would protect nothing the consumer role does not.
- The proxy identity is one key per server. Rotating it means setting every
  sensitive secret again; per-organization identities can come later.
- No per-service logic, and no credentials issued by providers on the
  owner's behalf: both would tie EnvRune to particular services.
