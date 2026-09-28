# Security model

EnvRune is designed to reduce routine accidental disclosure of environment
variables. It is not a replacement for operating-system isolation, a password
manager, endpoint protection, or a review process for production access.

## Vault protection

- Vault data is encrypted with XChaCha20-Poly1305.
- The master password is processed with Argon2id before it is used for vault
  encryption.
- The master password is never persisted by EnvRune.
- Vault writes use restrictive permissions and an atomic write path.
- The CLI does not send telemetry, emit secret values in routine status
  messages, or keep a background daemon running.

A forgotten master password cannot be recovered. Keep it in a password manager
or another recovery process that is appropriate for your environment.

## Runtime behavior

`envrune run` starts the requested child process directly rather than passing
the command through a shell. On Linux, immediately before `exec`, the runner
marks itself non-dumpable to reduce exposure through process-inspection paths
that honor that kernel control.

This is risk reduction, not an absolute guarantee. In particular, EnvRune does
not protect a live secret from root, a hostile administrator, or malicious code
already running as the same user with sufficient access.

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
- A process launched by `run` receives its resolved variables.

`export` is deliberately conspicuous: it displays only variable names, warns
before writing, requires `YES`, and requires an additional confirmation when
the destination is within a Git worktree. Prefer `run` whenever the consumer
can be launched as a process.

## Operating guidance

1. Keep `envrune.yml` in version control only after checking that it contains
   references, never values.
2. Keep `.env` and `.env.*` files out of version control; delete temporary
   exports as soon as their consumer no longer needs them.
3. Use separate references for separate environments, for example
   `service.development` and `service.production`.
4. Lock the interactive shell when stepping away.
5. Treat terminal history, screenshots, crash reports, and copied text as
   possible disclosure paths.

If your threat model requires defenses beyond these boundaries, use EnvRune as
one component in a broader secret-management and access-control design.
