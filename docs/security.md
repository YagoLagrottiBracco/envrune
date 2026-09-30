# Security model

EnvRune is designed to reduce routine accidental disclosure of environment
variables. It is not a replacement for operating-system isolation, a password
manager, endpoint protection, or a review process for production access.

## Vault protection

- Vault data is encrypted with XChaCha20-Poly1305 under a random 256-bit data
  key.
- The data key is wrapped by a key derived from the master password with
  Argon2id (64 MiB, 3 passes) and, optionally, by a random 256-bit recovery
  key. Changing the password re-wraps the data key; it does not re-encrypt
  with a new one.
- The master password and the recovery key are never persisted by EnvRune.
- Vault writes use restrictive permissions and an atomic write path. The file
  is locked only while it is read or written, and each write first merges
  what other processes committed, so concurrent sessions never overwrite each
  other.
- The CLI does not send telemetry or emit secret values in status messages
  or errors. Errors name references, variables, and environments, which are
  metadata.

The recovery key is shown once, when the vault is created or when you run
`envrune recovery reset`. Anyone who has it can open the vault, so keep it
offline, the way you would keep a password manager's emergency kit. Without
the password and the recovery key, a vault cannot be opened.

Backups made with `envrune backup` are the encrypted vault file itself and
open with the password and recovery key that were valid when they were made.

## Agent and keychain

Both are optional and exist so that editors, hooks, and new terminals can
use the vault without a prompt. Both hand out the **data key**, which opens
the vault, so choose them knowingly.

- **Agent** (`envrune unlock --ttl 8h`): a background process keeps the data
  key in memory until the time limit or `envrune lock`.
  - On Linux and macOS it answers on a Unix socket with mode `0600` in your
    private data directory (or in `XDG_RUNTIME_DIR`/the temporary directory
    when that path is too long), and checks that the peer process belongs to
    your user. On Linux it is also marked non-dumpable.
  - On Windows it answers on a named pipe, created with
    `github.com/Microsoft/go-winio` (the library Docker and containerd use),
    whose protected DACL grants access to your user's SID only, so other
    users, administrators without your token, and low-integrity processes
    cannot open it. The pipe rejects remote clients, and the agent checks the
    client's user again. The CLI checks that the pipe's server runs as your
    user before asking for the key, so a pipe created first by someone else
    cannot pose as the agent.
  - Like `ssh-agent`, it protects against other users, not against malicious
    code already running as you.
- **Keychain** (`envrune keychain enable`): the data key is stored in Windows
  Credential Manager (protected by DPAPI), the macOS Keychain, or the Secret
  Service on Linux. It is available whenever you are logged in, with no time
  limit and no extra confirmation. `envrune keychain disable` deletes it.

Changing the master password does not invalidate agent or keychain entries,
because the data key stays the same. After a restore, EnvRune turns keychain
unlock off and stops the agent.

## Runtime behavior

`envrune run`, named commands, and `envrune up` start the requested process
directly rather than passing the command through a shell. On Linux,
immediately before `exec`, the runner marks itself non-dumpable to reduce
exposure through process-inspection paths that honor that kernel control.

This is risk reduction, not an absolute guarantee. In particular, EnvRune does
not protect a live secret from root, a hostile administrator, or malicious code
already running as the same user with sufficient access.

## Input

Secret prompts never echo. If more input is already waiting after a secret
line, as happens when a multi-line block is pasted, EnvRune discards all of it
instead of storing the first line and running the rest as commands. `set`
asks for each value twice.

## Team files

`envrune.team.json` is encrypted to each member's X25519 public key, in the
style of age: a random file key encrypts the secrets with XChaCha20-Poly1305,
and it is wrapped per member with an ephemeral X25519 exchange and
HKDF-SHA256. The member list is bound to the ciphertext as authenticated
data. Each member's private key lives in their vault; a CI identity lives in
the `ENVRUNE_IDENTITY` secret.

Limits of the model:

- Removing a member re-encrypts the file for everyone else, but the removed
  member keeps what they already read and what is in Git history. Rotate
  those secrets.
- Anyone who can push to the repository can replace the file with one
  encrypted to other keys. Review changes to `envrune.team.json` as access
  changes.

## Local dashboard

The UI listens only on loopback and exists only while its foreground command is
running. It uses a one-time link fragment to establish a short-lived browser
session and does not place the token in a query string or browser storage.

The dashboard intentionally exposes metadata—references, bindings, and
availability—not secret values. It checks loopback Host and Origin, uses CSRF
protection for the lock action, and returns no-store and restrictive browser
headers. See [Local dashboard](local-ui.md) for the complete interaction
model.

## Plaintext boundaries

Some operations necessarily touch plaintext:

- `set` accepts a value through a hidden interactive prompt.
- `import` reads an existing dotenv file.
- `export` creates a dotenv file for a consumer that requires one.
- `copy` puts a value on the clipboard. It clears it after 30 seconds if it
  is still there. On Windows the value is excluded from clipboard history and
  cloud sync; clipboard managers on other systems may still record it.
- `env` and the terminal hook put values into a shell, where every command
  started from it can read them. `env` refuses to print to a terminal.
- `push github` sends values to GitHub Actions secrets through `gh`.
- A process launched by `run`, a named command, or `up` receives its resolved
  variables.

`export` is deliberately conspicuous: it displays only variable names, warns
before writing, requires `YES`, and requires an additional confirmation when
the destination is within a Git worktree. Prefer `run` whenever the consumer
can be launched as a process.

## Operating guidance

1. Keep `envrune.yml` in version control only after checking that it contains
   references, never values. `envrune doctor` flags lines that look like
   values.
2. Keep `.env` and `.env.*` files out of version control; delete temporary
   exports as soon as their consumer no longer needs them. `envrune doctor`
   lists the ones it finds.
3. Use separate references for separate environments, for example
   `service.development` and `service.production`.
4. Lock the interactive shell and run `envrune lock` when stepping away.
5. Treat terminal history, screenshots, crash reports, and copied text as
   possible disclosure paths.

If your threat model requires defenses beyond these boundaries, use EnvRune as
one component in a broader secret-management and access-control design.
