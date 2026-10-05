# Your first team on EnvRune Cloud

This walks two people through sharing a secret for the first time: **you**,
who create the organization, and **a teammate**, who joins it. It takes
about fifteen minutes and a call, or any channel the server does not
control, to read fingerprints to each other.

Do it once with a throwaway secret before the team depends on it. Each step
says what you should see; [cloud.md](cloud.md) explains every command in
full.

You both need the `envrune` command, a vault (`envrune init`), and the
address of your EnvRune Cloud server, written here as
`https://cloud.example.com`.

## 1. Both: sign in and set up your keys

```sh
envrune login --server https://cloud.example.com
envrune cloud init
envrune cloud doctor
```

`cloud init` shows a **recovery key** on a screen of its own and asks you to
type one of its groups back. Write it on paper or in a password manager
first. It never goes into a chat, an issue, or a synced note: if it does,
replace it with `envrune cloud recovery reset`.

`cloud doctor` should end without an error. If it says the server's database
is behind, whoever runs the server has migrations to apply
([self-hosting.md](self-hosting.md)).

## 2. You: create the organization and a secret

```sh
envrune cloud org create acme
envrune cloud project create acme shop
envrune cloud env create acme/shop/production
envrune cloud set acme/shop/production/demo-key
```

`set` asks for the value twice and never shows it.

## 3. Teammate: read your fingerprint out loud

```sh
envrune cloud whoami
```

Read the **account fingerprint** to the person adding you, on the call.

## 4. You: add the teammate

```sh
envrune cloud member add acme teammate@example.com --role maintainer --scope shop/*
```

It shows the fingerprint the server has for that address. Continue only if
it is the one you just heard: a different one means the key is not theirs.

The command ends by printing an invitation, such as:

```sh
envrune cloud org join acme --fingerprint K7QD-2MXA-P9FE-…
```

Read it to the teammate on the call. Do not send it through anything the
server could change.

## 5. Teammate: join and read the secret

```sh
envrune cloud org join acme --fingerprint K7QD-2MXA-P9FE-…
envrune cloud sync
envrune cloud copy acme/shop/production/demo-key --clear-after 30s
```

`copy` puts the value on the clipboard for thirty seconds. Paste it
somewhere private and check that it is what was stored in step 2.

## 6. Both: use it from a project

In a project's `envrune.yml`:

```yaml
version: 1
project: shop
cloud: acme/shop
environments:
  production:
    DEMO_KEY: cloud.demo-key
```

```sh
envrune run --env production -- printenv DEMO_KEY
```

The program receives the value on each of your devices, without it ever
having been in a file or a message. What it prints comes out masked: `run`
hides secret values in a program's output. `--no-redact` shows them, for
roles that may see values.

## 7. You: change a value, and see it arrive

```sh
envrune cloud set acme/shop/production/demo-key     # a new value
envrune cloud status acme/shop/production
```

`status` shows who already has the current value. The teammate's next
`envrune run` fetches it by itself; nobody runs a pull.

## 8. You: try a role that cannot see

```sh
envrune cloud org show acme                          # the teammate's user id
envrune cloud member set acme <user-id> --role consumer --scope shop/production
```

Now the teammate's `envrune run` still works, and `envrune cloud copy` is
refused: a consumer runs programs with a value without being shown it.

## 9. You: remove the teammate, and replace what they saw

```sh
envrune cloud member remove acme <user-id>
envrune cloud rotation acme
```

`member remove` starts new keys, so nothing written from now on reaches
them. `rotation` lists the values they had fetched, which they may still
know: replace each one (`envrune cloud set …`) or accept that it stays
(`envrune cloud rotation accept …`).

Add them again as in step 4 when you are done.

## If something does not match this page

Run `envrune cloud doctor` on the device where it happened, and the failing
command again with `--verbose` right after `envrune`. Neither prints a
value. [cloud-operations.md](cloud-operations.md) covers what an owner does
when something goes wrong for real: a lost device, a compromised project,
rules, notifications, and access for a limited time.
