# Envrune

Envrune is a Linux-first, local-first manager for encrypted environment variables.

Phase 1 establishes the encrypted local-vault core. The master password is never persisted.

## Safe usage

Run `envrune init`, then `envrune set openai.personal`, and list reference names with
`envrune list`. Values and master passwords are requested only from an interactive terminal.

There is no network behavior in this phase. A forgotten master password cannot be recovered.
Envrune reduces accidental disclosure but cannot protect secrets from root or malicious code
running as the same user while the command is active.
