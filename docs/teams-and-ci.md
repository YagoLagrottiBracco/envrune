# Teams and CI

## Sharing secrets with a team

Each vault belongs to one person. To share secrets without a server,
EnvRune keeps them in `envrune.team.json`, next to `envrune.yml`. This file is
meant to be committed. It is encrypted to every member's public key, in the
style of [age](https://age-encryption.org) and
[sops](https://github.com/getsops/sops):

- each member has an X25519 key pair; the private key lives in their vault;
- the secrets are encrypted with a random file key (XChaCha20-Poly1305);
- the file key is wrapped once per member, with X25519 and HKDF-SHA256;
- the member list is authenticated with the secrets, so it cannot be edited
  without re-encrypting.

References that start with `team.` resolve from this file. Everything else
still comes from your personal vault, so one `envrune.yml` can mix both.

### Setting it up

The first member creates the file:

```sh
envrune team init alice
envrune set team.stripe.test-key          # stored in envrune.team.json
envrune link STRIPE_KEY team.stripe.test-key
git add envrune.team.json envrune.yml && git commit -m "Share the Stripe test key"
```

A new member sends their public key:

```sh
envrune team whoami
# envrune-pub-3q2Vx...
```

Any existing member adds them and commits:

```sh
envrune team add bob envrune-pub-3q2Vx...
git commit -am "Add Bob to the team secrets"
```

Other commands: `team members`, `team list`, `team unset <team.reference>`,
and `team remove <name>`.

Removing a member re-encrypts the file for the others, but it cannot take
back what they already read or what is in Git history. Rotate the shared
secrets they had access to.

Anyone with write access to the repository can replace the file. Review
changes to `envrune.team.json`, particularly to its `members`, as you would
any change to access control.

## CI

A pipeline cannot type a password. There are two ways to give it secrets.

### A team identity (recommended)

Give the pipeline its own identity and add it as a team member. It then needs
no vault at all:

```sh
# On your machine, once:
envrune team keygen | gh secret set ENVRUNE_IDENTITY   # prints the public key
envrune team add ci envrune-pub-...
git commit -am "Give CI access to the team secrets"
```

`team keygen` creates an identity outside any vault. It writes the private
key (`envrune-key-...`) to standard output, here straight into a CI secret
named `ENVRUNE_IDENTITY`, and shows the public key. When no vault exists and
`ENVRUNE_IDENTITY` is set, EnvRune resolves `team.*` references from the team
file:

```yaml
# .github/workflows/test.yml
- name: Test
  env:
    ENVRUNE_IDENTITY: ${{ secrets.ENVRUNE_IDENTITY }}
  run: envrune run --env ci -- npm test
```

### A vault and its password

EnvRune also reads the master password from `ENVRUNE_PASSWORD_FILE` (a path,
which can be `/dev/fd/3`) or `ENVRUNE_PASSWORD`, and the vault location from
`ENVRUNE_VAULT`:

```yaml
- name: Restore the vault
  run: echo "$VAULT_B64" | base64 -d > "$RUNNER_TEMP/vault.ev1"
  env:
    VAULT_B64: ${{ secrets.ENVRUNE_VAULT_B64 }}
- name: Test
  env:
    ENVRUNE_VAULT: ${{ runner.temp }}/vault.ev1
    ENVRUNE_PASSWORD: ${{ secrets.ENVRUNE_PASSWORD }}
  run: envrune run --env ci -- npm test
```

Prefer a vault that holds only what CI needs. `ENVRUNE_PASSWORD_FILE` keeps
the password out of the environment of the processes EnvRune starts.

### Pushing to GitHub Actions secrets

When a workflow should read plain Actions secrets instead, copy an
environment with the [GitHub CLI](https://cli.github.com):

```sh
envrune push github --env production
envrune push github --env production --repo acme/shop --github-env production
```

EnvRune lists the variable names and asks for `YES`. Values go to `gh` on
standard input, never as arguments.
