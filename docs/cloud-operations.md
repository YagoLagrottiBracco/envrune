# Running a team on EnvRune Cloud: design

Status: **being implemented, in the order below.** These are the things an
owner does when something goes wrong, or wants to stop it going wrong:
a lost device, a compromised project, rules about who may fetch what,
notifications, and access for a limited time. They build on
[cloud-crypto.md](cloud-crypto.md) and change nothing in it: the server
still cannot read a value or add a recipient by itself.

One thing recurs. **The server can stop serving at once; only a device can
replace a key.** Every action here has those two halves: what the server
does immediately, and what an administrator's CLI finishes, because it
takes a signature or a key the server does not have.

## 1. A lost device

A member revokes their own device, from another device
(`envrune cloud device revoke <id>`) or from the panel, where a member sees
their devices.

- **At once, on the server:** the device stops being served, and the keys
  wrapped for it are deleted. The environments it held keys for are marked
  for a new epoch. A guided rotation opens, listing every secret the device
  fetched: whoever has the device may know those values.
- **Finished by a CLI:** `device revoke` starts the new epoch of every
  environment the member administers, and names the ones they do not, for
  someone who does (`envrune cloud rotate`). From the panel, where no key
  can be made, all of them wait for a CLI.

Revoking is a member's own act on their own device. An administrator who
needs to cut someone off removes the member.

## 2. A compromised project

`envrune cloud emergency <org/project>` is for when a project's secrets
must be assumed known. Only an owner may run it, after typing the project's
name.

- **At once, on the server:** every machine token that can reach the
  project is revoked. Every key wrapped for anyone but the device running
  the command, and that owner's recovery recipient, is deleted for the
  project's environments: no other device, of any member, can decrypt what
  comes next. A guided rotation opens that lists **every** secret of the
  project.
- **Finished by that CLI:** each environment gets a new epoch whose key is
  wrapped for that device and that recovery recipient only.

Nobody is removed and no device is revoked: memberships are the owner's to
review. Access comes back when an administrator runs `envrune cloud share`,
which wraps the new keys for the members and devices the chain still
allows, and tokens are created again. The values themselves stay as they
were until each one is replaced; the rotation list says which are left.

It does not end sign-in sessions. A session reads names and metadata, and
none of it decrypts anything; what an emergency takes away is the keys.

## 3. Rules about who may fetch

An organization may have **rules**, kept in a file an owner applies:

```yaml
# envrune.policy.yml
rules:
  - environments: "*/production"
    deny: [consumer]
  - environments: "shop/production"
    deny: [admin, maintainer, consumer]   # people never fetch it; machine tokens do
```

`environments` is `project/environment`, where either side may be `*`.
`deny` lists roles. A member whose role a matching rule denies is refused
the environment: its ciphertext, its keys, and the use of its sensitive
secrets. Rules never deny machine tokens, which have scopes of their own,
and never grant anything: they only take away.

`envrune cloud policy set <org> envrune.policy.yml` applies them (owners
only), `cloud policy show <org>` prints them, and the audit log records each
change. `doctor` says when an environment of the project is denied to you.

The server enforces rules; they are not signed. A compromised server could
ignore them, as it could refuse service. They guard against mistakes in
granting scopes, not against the server.

## 4. Notifications

An organization may name one HTTPS address to be told about what happens:

```sh
envrune cloud webhook set <org> https://hooks.example.com/envrune
```

The server sends each event as a JSON document: the action, the target, who
did it, and when. It is what the audit log holds, so it never contains a
value. Every request carries `X-EnvRune-Signature`, the HMAC-SHA256 of the
body with a secret shown once when the webhook is set, so the receiver can
tell it came from the server.

Events are the audit log's entries except the frequent ones (fetches, use,
and forwarded requests). Delivery is tried when something happens and again
by a scheduled request, with a limit on attempts; an address that keeps
failing is reported in the panel and by `cloud webhook show`.

EnvRune knows no chat or mail service. Anything that accepts a webhook can
receive these, directly or through whatever the team already uses to route
them.

## 5. Access for a limited time

A member asks for access they do not have:

```sh
envrune cloud access request acme/shop/production --for 4h --reason "incident 214"
```

An owner or admin sees the request in the panel and in
`envrune cloud access list <org>`, and approves it from the CLI, which is
where memberships are signed:

```sh
envrune cloud access approve <request>     # or: deny
```

Approving signs a membership with the wider scope, as `member set` does,
and records until when it holds.

- **At the end of the time, on the server, by itself:** the wider part of
  the scope stops being served. The member cannot fetch the environment or
  use its sensitive secrets from then on, without anyone doing anything. A
  guided rotation opens for the secrets they fetched meanwhile.
- **Finished by a CLI:** the next time an administrator's CLI talks to the
  server, it signs the member's scope back to what it was and starts a new
  epoch for the environment. `envrune cloud access list` shows what is
  waiting for that.

Between the two, the member's device may still hold a key and a copy from
before the time ran out; an organization that needs that gap closed sets an
offline limit ([cloud.md](cloud.md#limiting-offline-use)).

## Order

1. A lost device.
2. A compromised project.
3. Rules.
4. Notifications.
5. Access for a limited time.
