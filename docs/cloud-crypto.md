# EnvRune Cloud: cryptographic design

Status: **approved for the MVP**, with the proposals under
[Open questions](#open-questions-for-review) adopted; they can be revisited.
Implementation: `internal/cloudcrypto` (primitives), `internal/cloud` (the
CLI's client: verification, the local cache, and every operation below),
`cloud/web` (API and panel), `cloud/supabase` (schema). This document
describes how EnvRune Cloud shares secrets between the members of a team so
that the server never sees a value or a key that decrypts one.

## Goals

1. **Zero-knowledge by default.** The server stores ciphertext and metadata.
   A full copy of the database and the server's code and keys does not reveal
   a secret value.
2. **The server cannot grant itself access.** A compromised server must not be
   able to add a key of its own, or a member's key of its choosing, and have
   clients encrypt project keys to it without anyone noticing.
3. **Offline and local first.** The CLI keeps working with the last synced
   state, and the local mode (no account) keeps working as today.
4. **Leaving a team means losing future access.** Removing a member rotates
   the keys they held and walks the owner through rotating the values they
   could read.
5. **Recoverable.** A user who loses every device gets their access back
   with the recovery key shown once at sign-up.

Non-goals, stated so they are not assumed:

- Protecting a value from a member who is allowed to use it. A `consumer`
  can run a program with a value, so they can extract it on their own
  machine. Roles restrict what the CLI and the panel do; Phase 5 (injection
  proxy and temporary credentials) addresses keeping values off machines.
- Hiding metadata. Names of organizations, projects, environments, variables,
  and references, membership, roles, and the audit log are visible to the
  server. Names are not secret in EnvRune (see the security invariants).
- Protecting against a malicious panel. The panel is code the server sends to
  the browser, so the panel never decrypts values in this design (see
  [The web panel](#the-web-panel)).

## Stack and where each piece runs

| Piece | Runs on | Holds |
| --- | --- | --- |
| API and panel: Next.js (App Router, route handlers) | Vercel | No keys to secrets. The Supabase service role key only on the server side. |
| Database, auth, realtime: Supabase (Postgres, Auth, Realtime) | Supabase Cloud | Ciphertext, wrapped keys, public keys, signatures, metadata, audit log. |
| CLI (`envrune`) | Developer machines, CI | Device private keys and decrypted project keys, inside the local vault. |

Everything is self-hostable: Supabase publishes a Docker setup, and the API
and panel build into one Docker image that takes its configuration when it
starts. [self-hosting.md](self-hosting.md) describes running both on your
own infrastructure; the CLI takes the server address from
`envrune login --server <url>`.

The CLI talks only to the Next.js API (`/api/v1/...`), never to Supabase
directly, so the protocol can outlive the choice of database. The API
forwards the user's Supabase session so Postgres row-level security (RLS)
applies to every query; RLS decides who may **fetch** ciphertext, while
encryption decides who can **read** it.

Code layout: `cloud/web` (Next.js), `cloud/supabase` (migrations, RLS
policies, tests), and `internal/cloud` in the CLI.

## Primitives

Only standard constructions from maintained libraries; no new cryptography.

| Use | Primitive | Library |
| --- | --- | --- |
| Encrypting a key to a device or a machine | age, X25519 recipients | `filippo.io/age` |
| Encrypting values | XChaCha20-Poly1305 with associated data | `golang.org/x/crypto/chacha20poly1305` (already used by the vault) |
| Signatures | Ed25519 | Go `crypto/ed25519` |
| Deriving keys from the recovery key | HKDF-SHA256 | Go `crypto/hkdf` |
| Fingerprints | SHA-256, shown as 6 groups of 4 base32 characters | Go `crypto/sha256` |
| Randomness | OS CSPRNG | Go `crypto/rand` |

age replaces the ad-hoc X25519+HKDF+XChaCha wrapping of
`envrune.team.json` for the cloud: it is a reviewed format with the same
building blocks.

## Keys

```text
recovery key (32 random bytes, shown once)
 └─ HKDF "envrune-recovery-backup-v1" ─▶ key that encrypts the recovery backup:
      the account private key and the recovery age identity (random X25519)

account key (Ed25519), one per user
 └─ signs ─▶ device certificates: this device's keys belong to this user

device keys, one set per device, private parts only in the local vault
 ├─ age identity (X25519)   ◀─ environment keys are encrypted to it
 └─ signing key (Ed25519)   ─▶ signs values it writes and keys it wraps

environment key (32 random bytes), one per project environment and epoch
 └─ encrypts ─▶ secret values (XChaCha20-Poly1305)

organization root = the founder's account public key, pinned by every member
 └─ signs, directly or through admins ─▶ membership certificates
```

### Account key and recovery key

At sign-up the CLI generates the account key and the recovery key, shows the
recovery key once (like the local vault's), and uploads:

- the account public key;
- the recovery backup: the account private key and a random recovery age
  identity, encrypted with the key derived from the recovery key
  (XChaCha20-Poly1305, associated data = user id). age has no way to build an
  identity from derived bytes, so the identity is random and travels in the
  backup;
- the recovery age recipient, signed by the account key like a device, which
  is then included whenever an environment key is wrapped for this user.
  Clients check that signature, so the server cannot substitute a recipient
  of its own.

The account private key is also kept on each trusted device, in the vault.

### Devices

Each device generates its age identity and signing key locally and stores
the private parts in the local vault, encrypted by the vault's data key like
every other secret. A device is **trusted** once a certificate for it exists:

```text
device certificate = sign(account key,
  "envrune-device-v1" ‖ user id ‖ device id ‖ age recipient ‖ signing public key ‖ created at)
```

A new device gets its certificate in one of two ways:

1. **Approval by a trusted device.** The new device uploads a request
   (`envrune cloud init`); the user runs `envrune cloud device approve <id>`
   on a trusted device. Both screens show the same fingerprint of the new
   device's keys, and the user confirms they match. The trusted device signs
   the certificate, encrypts the account private key to the new device with
   age (so it can certify devices and sign memberships too), and wraps the
   environment keys this user holds to it. The new device accepts the
   account key only if it is the registered one and it certified exactly
   this device's keys.
2. **Recovery.** The user types the recovery key on the new device, which
   decrypts the account key backup, signs its own certificate, and uses the
   recovery age identity to unwrap the environment keys wrapped for this
   user, then wraps them to itself.

An admin can also approve a member's device, as the spec asks, by signing a
membership certificate for a new account key (see below); this is the path
for "I lost everything and the recovery key".

### Organizations, members, and trust

The CLI must not trust the server to say which public key belongs to whom.
Every public key a client encrypts to is reached through a chain of
signatures that ends at the **organization root**:

- Creating an organization pins the founder's account public key as its
  root. Each member's CLI stores the root the first time it joins, and shows
  its fingerprint (`envrune cloud org show`); an invitation link also carries it,
  so a member can compare it out of band.
- A **membership certificate** is signed by the root or by an admin whose own
  membership certificate chains to the root:

  ```text
  sign(admin account key, "envrune-member-v1" ‖ org id ‖ user id ‖
       member account public key ‖ role ‖ scope (projects, environments) ‖ issued at)
  ```

- To add a member, the admin's CLI asks the server for the member's account
  key by email and shows its fingerprint; the admin confirms it with the new
  member out of band (both run `envrune cloud whoami`) before signing. This
  is the one moment a lying server could insert a key of its own, and the
  fingerprint comparison is what catches it.
- Before wrapping an environment key to a device, the CLI verifies: device
  certificate ← member's account key ← membership certificate ← … ← pinned
  root, and that the role and scope allow that environment.

A compromised server can still hide members, refuse service, or show stale
data; it cannot make a client encrypt to a key no admin signed.

Removing an admin does not invalidate the certificates they issued before;
the removal certificate (signed like a membership certificate, with role
`removed`) is checked by clients, and the members that admin added are
listed for review.

### Environment keys and epochs

Each project environment has an environment key. Its **epoch** starts at 1
and increases on every rotation. For every device and machine allowed to
use the environment, and for the recovery recipient of every member, the
server stores:

```text
wrapped key = age.Encrypt(environment key, recipient)
wrapping record = { environment id, epoch, recipient id, wrapped key,
                    signature by the wrapping device over all of the above }
```

Clients accept a wrapped key only if the signature is by a trusted device of
a member allowed to administer that environment (owner, admin, maintainer),
or by another trusted device of the recipient themselves: when a user
approves a new device, their existing device shares the keys it already has.
The database enforces the same rule: only administrators wrap keys for
someone else.

### Secret values

```text
nonce = 24 random bytes
ciphertext = XChaCha20-Poly1305(environment key[epoch], nonce, value,
  associated data = "envrune-secret-v1" ‖ org id ‖ project id ‖ environment id ‖
                    secret name ‖ version ‖ epoch)
record = { ids, name, version, epoch, nonce, ciphertext, written by device,
           signature by that device over everything above }
```

- The associated data stops the server from moving a ciphertext to another
  secret, environment, or version: decryption fails.
- The signature tells readers which device wrote each version, for the audit
  trail and for rollback detection.
- Versions are kept; the CLI's `history` and `rollback` work the same way as
  in the local vault.
- Rollback protection: the CLI remembers the highest version and epoch it
  has seen for each secret and refuses to go back without `--allow-older`.

## Roles

| Role | Gets the environment key | CLI and panel allow |
| --- | --- | --- |
| owner | yes | everything, including deleting projects and changing owners |
| admin | yes | members, roles, environments, rotation, machine tokens |
| maintainer | yes | set, rotate, rollback, view values in the CLI |
| consumer | yes | `run`, `up`, `mcp`: values reach processes, never the screen; no `copy`, `export`, `env`, or reveal; output masking cannot be turned off |
| auditor | no | metadata and the audit log |

Because a consumer holds the environment key, these limits are enforced by
the client. They stop accidents and casual misuse; they do not stop a
consumer who modifies the CLI or inspects a running process. The documentation
and the panel say so.

## Removing a member

1. An admin signs a removal certificate. RLS immediately stops serving the
   project's ciphertext and wrapped keys to the member's devices.
2. The admin's CLI generates a new environment key (epoch + 1) for every
   environment the member could use, wraps it to the remaining devices and
   recovery recipients, and re-encrypts the **current** version of each
   secret under the new epoch.
3. Guided rotation starts: the panel and `envrune cloud rotation <org>` list
   every secret the member fetched ("this person could read these N
   secrets"). Each one waits until someone writes a new value
   (`envrune cloud set`, with `--generate` for a random one) or an owner or
   admin records that it stays as it is (`envrune cloud rotation accept`, or
   "Keep this value" in the panel).

Step 2 keeps the removed member from reading anything written from now on.
Only step 3 protects the values they already knew, so the two are recorded
apart: the values step 2 encrypts again under the new epoch are stored as
`secret.reencrypt` in the audit log and leave the rotation list untouched;
only a new value (`secret.write`) marks a secret rotated.

## Machine tokens (CI and deploys)

`envrune cloud token create acme --scope shop/production --expires 90d`
generates, on the admin's machine, a new age identity and signing key for
the machine, wraps the environment key to it, and prints one token:

```text
envrune_mt_<token id>.<API secret>.<age identity>.<org id>~<root user id>:<root key>~…
```

The server stores the token id, a hash of the API secret, the machine's
public keys, its scope, and its expiry. Only the CI system holds the private
age identity. The token also carries the organization's pinned roots, and
fetching an environment returns its membership certificates, so a CI job
verifies who wrapped the key and wrote each value the same way a member's
CLI does, with no local state. Revoking a token removes its access and marks the environment
for rotation, since the machine held the key.

## Local cache and offline use

After `envrune login`, the CLI keeps a cloud section in the local vault:
the device keys, the account key, the pinned organization roots, and the
last synced ciphertext and wrapped keys, all encrypted again by the vault's
data key. `run` and the other commands read from this cache, so they work
offline with the last synced state. `envrune cloud sync` (and every online
command) refreshes it.

### envrune.team.json

The team file stays what it is: the serverless way to share a few secrets
through Git, for teams without an account. It does not become the cloud
cache, for three reasons: it lives in the repository, while the cache
belongs to one user; it has no epochs, signatures, or roles; and mixing the
two would make a repository's contents depend on whether someone has an
account. `envrune cloud import-team` moves a team file's secrets into a cloud
project, after which the file can be deleted.

## References in envrune.yml

A project links itself to a cloud project with one line:

```yaml
cloud: acme/shop            # organization/project
environments:
  development:
    DATABASE_URL: cloud.database-url         # this project's environment of the same name
    SENTRY_DSN: cloud.acme.shared.production.sentry-dsn   # any cloud secret, fully named
    LOCAL_ONLY: personal.local-only          # the local vault, as today
```

`cloud.` references resolve from the cache; everything else resolves from
the local vault and the team file as today. They go to the cloud only when
envrune.yml has `cloud:`, so a file written before EnvRune Cloud whose local
references start with `cloud.` keeps its meaning. With `ENVRUNE_TOKEN` (a
machine token) they resolve from the server, verified against the roots the
token pins. Values from an environment where the user is a consumer are
marked, and the CLI refuses to show, copy, export, or push them, and to run
commands with `--no-redact`. Usage: [cloud.md](cloud.md).

## Audit log

The database functions append an entry, in the same transaction, for every
fetch of ciphertext, every write, rotation, membership change, device
approval or revocation, and token creation, use, or revocation, with the
user, the device or token, and the time. The table accepts inserts only (no
write policy, and triggers that reject updates, deletes, and truncation),
and each entry stores the SHA-256 of the previous one:

```text
hash = SHA-256(previous hash ‖ organization id ‖ time (UTC, microseconds) ‖
               user id ‖ device id ‖ token id ‖ action ‖ target ‖ detail)
```

Fields are separated by the unit separator (0x1F), and an absent user,
device, or token is skipped.

`envrune cloud audit export` downloads the log, computes every hash again,
and refuses a log where an entry was edited, removed, or inserted.
`envrune cloud audit verify` checks an exported file again, offline.

A chain proves that a log is consistent, not that it is the only one: a
server could compute a different log from the start. Two checks limit that.
Each device remembers the last entry it verified and refuses a later export
that lacks it, and `audit verify --since` checks that a new export still
holds every entry of an older one. Keep exports somewhere the server cannot
reach.

What it cannot record: a fetch shows that ciphertext left the server, not
that it was decrypted, and nothing records what a member does with a value
already in their cache. Entries are written by the server, so they are its
account of events: unlike values and keys, they carry no device signature.

## The web panel

The panel manages organizations, members, roles, devices, tokens, guided
rotation, and the audit log. It never decrypts values: it shows names,
versions, who changed what, and rotation state, and it cannot add a
member's key to a project by itself, since only a CLI with an admin's
account key can sign certificates and wrap keys. Approving a device or a
member in the panel creates a pending request that the admin completes with
`envrune cloud device approve` or `envrune cloud member add`, which show the
fingerprint to compare.

This keeps the zero-knowledge property independent of the JavaScript the
server sends. Showing or editing values in the browser can come later, as
an explicit opt-in with that trade-off explained.

## What a compromised server can and cannot do

| It can | It cannot |
| --- | --- |
| Read all metadata and the audit log | Read a value, an environment key, or a private key |
| Refuse service, or serve stale data to clients that have not seen newer versions | Serve a value older than one a client has seen without the client noticing |
| Hide a member or a device from listings, or hide a removal certificate from a client that has never seen it | Make a client encrypt to a key that no admin signed, or undo a removal a client has already seen (clients keep every certificate they have verified) |
| Record IP addresses and access times | Move a ciphertext to another secret, environment, or version |
| Keep ciphertext after a member is removed | Let a removed member read values written after the removal |

## Open questions for review

1. **Organization root recovery.** If the founder loses their devices and
   recovery key, the organization cannot sign new admins. Proposal: at
   creation, allow up to two more **root holders** whose account keys the
   founder signs as roots; any root can sign admins.
2. **Consumer and `mcp`.** Should `mcp --allow-any-command` be refused for
   consumers, since it turns masking into the only barrier? Proposal: yes.
3. **Offline expiry.** Should the cache expire (for example, 30 days without
   sync) so a removed member's laptop stops working on its own? It does not
   protect values they already had, but limits drift. Proposal: configurable
   per organization, off by default.
4. **Sign-in methods.** Supabase Auth with email links and GitHub OAuth for the
   MVP; SAML SSO and SCIM after it.
