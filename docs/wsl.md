# Windows and WSL

Windows and each WSL distribution have their own home directory, so by
default they each have their own vault:

| Where | Default vault |
| --- | --- |
| Windows | `%USERPROFILE%\.local\share\envrune\vault.ev1` |
| WSL | `~/.local/share/envrune/vault.ev1` (or `$XDG_DATA_HOME/envrune`) |

Two vaults are the simplest and safest setup. Use `envrune backup` and
`envrune restore` to copy one to the other when needed.

## One vault for both

Point WSL at the Windows vault with `ENVRUNE_VAULT` in `~/.bashrc` or
`~/.zshrc`:

```sh
export ENVRUNE_VAULT="/mnt/c/Users/<you>/.local/share/envrune/vault.ev1"
```

Both sides then read and write the same file. Keep these limits in mind:

- **Locking does not cross the boundary.** EnvRune locks the vault while it
  writes, with `LockFileEx` on Windows and `flock` in Linux. These locks do
  not see each other through `/mnt/c`. Every write is atomic, and each writer
  merges the latest version from disk first, but two writes at the very same
  moment, one on each side, can still lose one of them. Avoid changing
  secrets on both sides at once.
- **Some file systems cannot lock at all.** When `flock` is not supported,
  EnvRune continues without the lock rather than failing.
- **The agent is per side.** `envrune unlock` in Windows does not unlock WSL,
  and the other way around: the agent socket lives next to the vault, but a
  Windows process cannot answer a Linux one. Run `envrune unlock` on each
  side, or use the keychain on Windows and the agent in WSL.
- **`/mnt/c` is slower.** Each command reads the vault through the Windows
  file-system bridge.

## Running Windows tools from WSL, and back

`envrune run` starts any executable on `PATH`, including Windows programs
from WSL (`envrune run -- cmd.exe /c set`). The variables reach them through
WSL interop.

For `envrune copy` in WSL, EnvRune uses `clip.exe`, so the value lands in the
Windows clipboard. It cannot read that clipboard back, so it clears it after
the delay even if you copied something else meanwhile.
