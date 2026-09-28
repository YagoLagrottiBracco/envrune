# Envrune Native Windows Support and Complete README Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a native, security-honest Windows executable and a complete English README while preserving Envrune's local encrypted vault workflow on Linux.

**Architecture:** Platform-specific Go files provide Windows path selection, file replacement, locking, and URL opening behind focused interfaces. Shared vault, project, exporter, runner, and UI code remain platform-agnostic. The README describes the real command grammar and platform limits without ever displaying secret values.

**Tech Stack:** Go 1.27, `golang.org/x/sys/windows`, `golang.org/x/term`, PowerShell, Linux shell.

**Spec:** `docs/superpowers/specs/2026-09-28-envrune-windows-and-readme-design.md`

## Global Constraints

- Support native Linux `amd64` and Windows `amd64`; end users run a binary and do not require Go.
- Keep one encrypted vault format, no network features, daemon, key cache, or secret-bearing temporary file.
- `envrune run` must directly start the selected program, never a command shell.
- Linux keeps `PR_SET_DUMPABLE`; Windows documentation must state it has no equivalent in this release.
- All messages and documentation are English and must not echo values or passwords.
- Windows vault files live in `%LOCALAPPDATA%\Envrune\vault.ev1`; Linux keeps the XDG path.

## Review Focus

- A missing `LOCALAPPDATA` must fall back to the current user's AppData path, not a POSIX `/.local/share` path.
- A second Windows process attempting the same vault lock must fail safely rather than write concurrently.
- Replacing an existing vault, project YAML, or forced plaintext export on Windows must not fail because the destination already exists.
- A Windows `run` command with metacharacters in an argument must remain an argument to the direct child program, not execute shell syntax.
- README examples must contain only references/placeholders and must warn before plaintext export.

---

### Task 1: Native vault path selection

**Files:**
- Modify: `internal/paths/data.go`
- Modify: `internal/paths/data_test.go`

**Interfaces:**
- Consumes: `VaultPath(getenv func(string) string, homeDir func() (string, error)) (string, error)`.
- Produces: the same public signature with a native default chosen using `runtime.GOOS` and `filepath.Join`.

- [ ] **Step 1: Write failing path tests**

Add platform-conditional assertions that Windows chooses a supplied
`LOCALAPPDATA` value followed by `Envrune\vault.ev1`, falls back to
`home\AppData\Local\Envrune\vault.ev1`, and never treats `XDG_DATA_HOME`
as a Windows default. Preserve Linux's XDG and home fallback assertions.

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `go test ./internal/paths -run TestVaultPath -count=1`

Expected: FAIL because the current implementation always constructs an XDG
path with POSIX `path.Join`.

- [ ] **Step 3: Implement native path selection in `VaultPath`**

Use `filepath.Join`. On Windows prefer `LOCALAPPDATA`, then the user's
`AppData\Local`; on non-Windows retain `XDG_DATA_HOME`, then
`.local/share`. Keep error propagation from `homeDir` unchanged.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `go test ./internal/paths -run TestVaultPath -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/paths/data.go internal/paths/data_test.go
git commit -m "feat: use native Windows vault path"
```

### Task 2: Cross-platform atomic replacement

**Files:**
- Create: `internal/atomicfile/replace_other.go`
- Create: `internal/atomicfile/replace_windows.go`
- Create: `internal/atomicfile/replace_test.go`
- Modify: `internal/vault/store.go`
- Modify: `internal/project/config.go`
- Modify: `internal/exporter/write.go`
- Modify: `internal/vault/store_test.go`
- Modify: `internal/project/config_test.go`
- Modify: `internal/exporter/write_test.go`

**Interfaces:**
- Produces: `atomicfile.Replace(source, destination string) error`.
- Consumes: completed, synced temporary files in the same directory as their
  destination.
- Consumers: vault `Commit`, project `WriteAtomic`, and forced exporter
  `Write` replace only after temporary file creation and close succeed.

- [ ] **Step 1: Write failing atomic-replacement tests**

Add `TestReplaceReplacesExistingDestination` with literal old/new file
contents. Extend vault, project, and exporter tests so each writes an existing
destination a second time; exporter uses `force=true`. Assert the final
content/data is the second write and the temporary source no longer exists.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./internal/atomicfile ./internal/vault ./internal/project ./internal/exporter -count=1`

Expected: FAIL because `atomicfile.Replace` does not exist and current call
sites invoke `os.Rename` directly.

- [ ] **Step 3: Implement `atomicfile.Replace` and route all three writers through it**

For non-Windows, implement `Replace` with `os.Rename`. For Windows, use
`windows.MoveFileEx` with replace-existing and write-through flags. Preserve
the existing same-directory temporary-file, close, cleanup, and parent-sync
ordering; do not add a delete-before-replace path.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `go test ./internal/atomicfile ./internal/vault ./internal/project ./internal/exporter -count=1`

Expected: PASS on Windows and Linux.

- [ ] **Step 5: Commit**

```bash
git add internal/atomicfile internal/vault/store.go internal/vault/store_test.go internal/project/config.go internal/project/config_test.go internal/exporter/write.go internal/exporter/write_test.go
git commit -m "feat: replace encrypted files atomically on Windows"
```

### Task 3: Real Windows locks for vault and project writes

**Files:**
- Create: `internal/vault/lock_windows.go`
- Modify: `internal/vault/lock_other.go`
- Create: `internal/vault/lock_windows_test.go`
- Create: `internal/project/lock_windows.go`
- Modify: `internal/project/lock_other.go`
- Create: `internal/project/lock_windows_test.go`

**Interfaces:**
- Consumes: existing package-local `acquireLock(path string) (*vaultLock, error)`
  and `lockConfig(path string) (*configLock, error)` signatures.
- Produces: Windows implementations backed by `windows.LockFileEx` and
  `windows.UnlockFileEx`; unsuccessful non-blocking acquisition maps to
  `vault.ErrCannotUnlock` and `project.ErrProjectBusy` respectively.

- [ ] **Step 1: Write Windows-only contention tests**

Create `//go:build windows` tests that acquire a lock, attempt a second
acquisition of the same path, assert the package's safe busy error, close the
first lock, then assert a fresh acquisition succeeds. Do not launch a shell or
depend on timing.

- [ ] **Step 2: Run the Windows lock tests to verify they fail**

Run: `go test ./internal/vault ./internal/project -run 'Test.*Lock.*Contention' -count=1`

Expected: FAIL because Windows currently compiles the no-op `!linux` lock
files.

- [ ] **Step 3: Implement Windows lock files and narrow the fallback build tags**

Use an exclusive one-byte `LockFileEx` range at offset zero with the
fail-immediately flag. Keep the `*os.File` and `windows.Overlapped` on each lock for matching
unlock and close. Change fallback files to `!linux && !windows` so a supported
Windows build cannot silently select a no-op lock.

- [ ] **Step 4: Run the Windows lock tests to verify they pass**

Run: `go test ./internal/vault ./internal/project -run 'Test.*Lock.*Contention' -count=1`

Expected: PASS on a native Windows host.

- [ ] **Step 5: Commit**

```bash
git add internal/vault/lock_windows.go internal/vault/lock_other.go internal/vault/lock_windows_test.go internal/project/lock_windows.go internal/project/lock_other.go internal/project/lock_windows_test.go
git commit -m "feat: lock Envrune files on Windows"
```

### Task 4: Native Windows browser and binary workflow

**Files:**
- Modify: `internal/cli/ui.go`
- Create: `internal/cli/browser_linux.go`
- Create: `internal/cli/browser_windows.go`
- Create: `internal/cli/browser_other.go`
- Create: `internal/cli/browser_windows_test.go`
- Modify: `internal/runner/run_test.go`
- Create: `scripts/build.ps1`
- Create: `scripts/build.sh`
- Create: `scripts/build-release.ps1`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `browserCommand(address string) *exec.Cmd`, returning the native
  platform opener or nil when no opener is supported.
- Consumes: `serveUI`'s existing `openBrowser(address)` call and no secret
  values; the address is a one-time loopback URL.

- [ ] **Step 1: Write failing browser-command and build-output tests**

Add a Windows-only test that asserts `browserCommand` uses `rundll32.exe` with
`url.dll,FileProtocolHandler` and passes the supplied loopback address as one
argument. Add a runner helper-process test that passes a literal metacharacter
argument through `Run` and asserts the helper receives that exact argument,
proving the runner did not insert a shell. Add a script-level verification
command that checks `bin/envrune.exe` exists after the PowerShell build script
runs, plus `dist/envrune-windows-amd64.exe` and `dist/envrune-linux-amd64`
after the release build script runs.

- [ ] **Step 2: Run the focused browser test to verify it fails**

Run: `go test ./internal/cli -run TestWindowsBrowserCommand -count=1`

Run: `go test ./internal/runner -run TestRunPassesMetacharactersLiterally -count=1`

Expected: FAIL because UI opening is hard-coded to Linux `xdg-open` and the
direct-child metacharacter regression test does not yet exist.

- [ ] **Step 3: Split browser command construction by platform and add build scripts**

Move command construction out of `ui.go`; preserve the existing Linux
`xdg-open` behavior, return a Windows `rundll32.exe` command, and return nil
for unsupported platforms. `scripts/build.ps1` builds
`bin/envrune.exe`; `scripts/build.sh` builds `bin/envrune`. Both use
`go build -trimpath` and fail when Go is unavailable. `scripts/build-release.ps1`
cross-builds the two documented release names into `dist`. Keep generated
binaries and `dist` ignored by Git.

- [ ] **Step 4: Verify native builds and focused test**

Run:

```powershell
go test ./internal/cli -run TestWindowsBrowserCommand -count=1
go test ./internal/runner -run TestRunPassesMetacharactersLiterally -count=1
./scripts/build.ps1
Test-Path .\bin\envrune.exe
./scripts/build-release.ps1
Test-Path .\dist\envrune-windows-amd64.exe
Test-Path .\dist\envrune-linux-amd64
```

Run on Linux:

```sh
./scripts/build.sh
test -x ./bin/envrune
```

Expected: browser test passes and each native platform produces its ignored
binary at the documented location.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/ui.go internal/cli/browser_*.go internal/cli/browser_windows_test.go internal/runner/run_test.go scripts/build.ps1 scripts/build.sh scripts/build-release.ps1 .gitignore
git commit -m "feat: add native Windows build workflow"
```

### Task 5: Complete user README and release verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: exact CLI grammar in `internal/cli/command.go`, `shell.go`, and
  `ui.go`; data locations from `paths.VaultPath`.
- Produces: the start-to-finish English user guide described by the spec.

- [ ] **Step 1: Write a README content checklist**

Create a temporary review checklist from the spec covering Windows/Linux
installation, no-Go binary use, first-use confirmation, shell and one-shot
commands, YAML references, UI, export warning, paths, backup, limitations, and
troubleshooting. List every command example that will be checked for a value
or credential.

- [ ] **Step 2: Confirm the old README is incomplete against the checklist**

Run: `rg -n "Windows|LOCALAPPDATA|backup|troubleshoot|export|envrune.yml" README.md`

Expected: missing sections demonstrate the current README cannot yet serve as
the complete guide.

- [ ] **Step 3: Rewrite `README.md` as the complete English guide**

Use only the actual commands and safe placeholder references. Include release
binary use first, source builds second, and state that a future unsigned
Windows binary may show SmartScreen. Explain that copying the encrypted vault
is a backup, never a password recovery mechanism. Keep `export` visibly marked
as a deliberate plaintext exception.

- [ ] **Step 4: Verify documentation and all platform behavior**

Run:

```powershell
go test ./... -count=1
$env:GOOS='windows'; $env:GOARCH='amd64'; go build -trimpath -o .\bin\envrune.exe .\cmd\envrune
$env:GOOS='linux'; $env:GOARCH='amd64'; go build -trimpath -o .\bin\envrune .\cmd\envrune
rg -n -i "sk-[a-z0-9]|api[_ -]?key\s*=|password\s*=" README.md
```

Expected: full suite passes, both binaries build, and the README scan finds no
credential-shaped examples. Inspect any nonzero scan result before declaring
completion.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: complete Envrune user guide"
```
