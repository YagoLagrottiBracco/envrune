# Envrune

Envrune is a Linux-first, local-first manager for encrypted environment variables.

The master password is never persisted. The vault, derived key, and secret values stay local.

## Safe usage

On first use, run `envrune` with no command. It asks for confirmation before
creating the encrypted vault, then securely asks you to set and confirm the
master password. It never creates a vault unless you explicitly answer yes.

```sh
envrune
```

You can also initialize explicitly. After that, use the interactive shell for
normal work:

```sh
envrune init
envrune shell
```

`envrune shell` asks for the master password once, keeps the opened vault only in the foreground process memory, and displays the prompt `envrune [unlocked] >`. Use `set`, `list`, `link`, `usage`, `generate`, `import`, `run`, `export`, or `ui` there. Run `lock` or `exit` to wipe the session and release the vault lock.

One-shot commands such as `envrune set openai.personal` remain available and request the password for each invocation. Values and master passwords are requested only from an interactive terminal.

Terminal feedback is English and colored when output is an interactive terminal. Set `NO_COLOR=1` to force plain text; redirected output is always plain text without ANSI sequences.

There is no network behavior. A forgotten master password cannot be recovered.
Envrune reduces accidental disclosure but cannot protect secrets from root or malicious code
running as the same user while the command is active.
