# Keeping values out of Git

`envrune guard` stops a commit that would add a vault value to a repository.
It compares the staged changes with the values in your vault, and in the
project's team file when you are a member, and names the file, the line, and
the reference, never the value:

```text
$ git commit -m "wire up payments"
[ERROR] settings.py:14 contains the value of stripe.live-key
[ERROR] Commit blocked: 1 vault value is staged. Remove them and use the reference through envrune.yml instead, or bypass this check once with `git commit --no-verify`.
```

## Turning it on

In each repository:

```sh
envrune guard install     # writes .git/hooks/pre-commit (or core.hooksPath)
envrune guard uninstall   # removes it again
```

`install` does not replace a pre-commit hook it did not write. If you already
have one, add a line that runs `envrune guard` to it, or add EnvRune to your
hook manager. With [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: envrune-guard
        name: envrune guard
        entry: envrune guard
        language: system
        pass_filenames: false
```

With Husky, add `envrune guard` to `.husky/pre-commit`.

You can also run `envrune guard` by hand at any time to check what is staged.

## When the vault is locked

A hook must not stop to ask for a password, so `guard` unlocks only through
`ENVRUNE_PASSWORD`/`ENVRUNE_PASSWORD_FILE`, a running agent
(`envrune unlock`), or the system keychain. When none of them is available, it
warns that the changes were not checked and lets the commit through.
`envrune guard --strict` blocks the commit instead; use it in a hook manager
when you want no unchecked commits.

## What it checks

- The lines that the staged changes add, in added, copied, modified, and
  renamed files. Lines that are removed are not checked.
- Each value, its URL-encoded forms, and its base64 encodings, as described in
  [Output redaction](redaction.md). The added lines of a file are searched
  together, so a value that spans lines, such as a PEM private key, is found.
- Values of at least six characters.

It does not check binary files, values transformed in other ways (split,
reversed, hex-encoded, encrypted), or commits made with `--no-verify`. The
comparison happens in memory; EnvRune does not store hashes of your values
for this.

## Finding values that already leaked: `envrune scan`

`guard` stops new leaks; `scan` finds old ones. It searches the files under
a folder and everything every commit on every branch added:

```text
$ envrune scan
[ERROR] stripe.live-key appears in 2 places:
  logs/app.log:2
  commit d53c8cb (2026-05-03, Alice): config.py:14
[WARNING] Found 1 leaked value in 214 files and 87 commits. Rotate each value that may have left this machine (`envrune rotate <reference>` or at its provider); removing it from files or history does not make it secret again.
```

```sh
envrune scan                        # this folder and its Git history
envrune scan ../other-repo logs/    # other folders and files
envrune scan --no-history           # files only
```

It exits with code 1 when it finds a value, so it can run in CI. It skips
`.git`, `node_modules`, `.venv`, `venv`, and `__pycache__`, and files that look
binary (a NUL byte in their first 8 KiB). It does not see stashes, reflog
entries, or commits that no branch or tag reaches.

A value found in history has been exposed to everyone who cloned the
repository. Rewriting history (for example with `git filter-repo`) hides it
from new clones, but only rotating it makes the old value useless.
