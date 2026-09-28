# Envrune Session Shell and CLI Feedback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a one-password, in-memory Envrune shell with clear English visual feedback while preserving local-vault security guarantees.

**Architecture:** `app.Session` keeps one opened vault and its derived key in the foreground `envrune shell` process, and is responsible for locking and zeroing its memory. The CLI adds a session REPL and a presentation layer which owns English outcome copy and terminal-only ANSI styling. The loopback UI consumes the session's metadata-only snapshot when launched inside the shell.

**Tech Stack:** Go 1.27, standard library, `golang.org/x/term`, existing Argon2id/XChaCha20 vault, embedded HTML/CSS/JavaScript.

**Spec:** `docs/superpowers/specs/2026-09-28-envrune-session-ux-design.md`

## Global Constraints

- The master password, derived key, session token, and plaintext values must never be persisted, logged, emitted, or passed through environment variables.
- `envrune shell` is one foreground process; no daemon, socket, or cross-terminal cache is permitted.
- Wipe vault keys, secret byte slices, and session state before releasing the vault lock on every close path.
- All user-facing CLI and local UI copy is English.
- ANSI output is enabled only for a terminal when `NO_COLOR` is absent and `TERM` is not `dumb`; redirected output stays plain.
- Preserve direct child execution, export confirmation, atomic writes, loopback-only UI, and no-secret-output rules.

## Review Focus

- An EOF or Ctrl+C during `envrune shell` must release the vault lock and make in-memory secret data unreachable; cover in Task 3.
- `NO_COLOR=1`, `TERM=dumb`, and a non-file writer must never receive ESC sequences; cover in Task 2.
- A malformed quoted shell line must be rejected without execution or echoing a supplied secret-looking token; cover in Task 3.
- A second CLI process while the shell is open must fail rather than write a stale vault; cover in Task 1.
- A session-launched UI must remain metadata-only and closing its browser session must not close the parent shell vault; cover in Task 4.

---

### Task 1: In-memory vault session and full close zeroization

**Files:**
- Modify: `internal/vault/store.go`
- Modify: `internal/vault/store_test.go`
- Create: `internal/app/session.go`
- Create: `internal/app/session_test.go`
- Modify: `internal/app/vault_service.go`
- Modify: `internal/app/dashboard.go`

**Interfaces:**
- Produces: `app.OpenSession(path string, password []byte) (*Session, error)` and `(*Session).Close()`.
- Produces: session equivalents of `Set`, `Generate`, `Import`, `List`, `Link`, `Usage`, and `ResolveEnvironment` without a password parameter.
- Produces: `(*Session).Snapshot() DashboardSnapshot` for a metadata-only UI source.
- Consumes: `vault.Opened` and existing domain, project, exporter, generator, and runner types.

- [ ] **Step 1: Write failing session lifecycle tests**

Add `TestSessionReusesOpenedVaultAndCloses` and `TestSessionLockBlocksConcurrentOpen` in `internal/app/session_test.go`. Initialize a temporary vault, open one session, mutate/list through it, assert a concurrent `vault.Open` fails, close it, and assert another open succeeds.

- [ ] **Step 2: Run the lifecycle tests to verify they fail**

Run: `go test ./internal/app -run 'TestSession(ReusesOpenedVaultAndCloses|LockBlocksConcurrentOpen)' -count=1`

Expected: FAIL because `OpenSession` and `Session` do not exist.

- [ ] **Step 3: Implement zeroizing `vault.Opened.Close` and `app.Session`**

Implement `vault.Opened.Close()` as idempotent: wipe the derived key and every value in `data.Secrets`, clear maps/project data, then close the lock once. Implement `Session` around exactly one opened vault, delegating operations against that value and atomically committing mutations. Add a package-private snapshot helper shared with `Dashboard` so metadata construction never copies values.

- [ ] **Step 4: Add and run session operation tests**

Add tests showing `Session.Set`, `List`, `Link`, and `ResolveEnvironment` work after a single open and their captured result never contains the stored sentinel. Run: `go test ./internal/app -count=1`.

Expected: PASS.

- [ ] **Step 5: Commit the session foundation**

```bash
git add internal/vault/store.go internal/vault/store_test.go internal/app/session.go internal/app/session_test.go internal/app/vault_service.go internal/app/dashboard.go
git commit -m "feat: add in-memory vault sessions"
```

### Task 2: Terminal presentation and English command outcomes

**Files:**
- Create: `internal/cli/presentation.go`
- Create: `internal/cli/presentation_test.go`
- Modify: `internal/cli/command.go`
- Modify: `internal/cli/ui.go`
- Modify: `internal/cli/command_test.go`

**Interfaces:**
- Produces: `Presenter` with `Success`, `Info`, `Warn`, and `Error` methods for safe user-facing text.
- Produces: `NewPresenter(stdout, stderr io.Writer, getenv func(string) string) Presenter` that chooses styling from writer/terminal state.
- Consumes: existing `Execute` and `executeUI` paths.

- [ ] **Step 1: Write failing presenter tests**

Add `TestPresenterWritesPlainTextWhenOutputIsNotATerminal`, `TestPresenterHonorsNoColor`, and `TestPresenterStylesTerminalOutput`. Assert each uses English text and terminal output includes the intended ANSI marker only when enabled.

- [ ] **Step 2: Run the presenter tests to verify they fail**

Run: `go test ./internal/cli -run TestPresenter -count=1`

Expected: FAIL because `Presenter` does not exist.

- [ ] **Step 3: Implement `Presenter` and migrate one-shot outcome messages**

Use four fixed semantic styles (green success, blue information, yellow warning, red error). Keep strings free of values. Make each successful existing command acknowledge its safe outcome; keep error copy general around unlock/secret resolution. Keep help and syntax output English and uncolored when captured.

- [ ] **Step 4: Run presentation and existing CLI tests**

Run: `go test ./internal/cli -count=1`

Expected: PASS, including no ANSI sequences in buffer-backed tests.

- [ ] **Step 5: Commit the presentation layer**

```bash
git add internal/cli/presentation.go internal/cli/presentation_test.go internal/cli/command.go internal/cli/command_test.go internal/cli/ui.go
git commit -m "feat: add clear terminal feedback"
```

### Task 3: Foreground `envrune shell` REPL

**Files:**
- Create: `internal/cli/shell.go`
- Create: `internal/cli/shell_test.go`
- Modify: `internal/cli/command.go`
- Modify: `internal/cli/prompt.go`
- Modify: `cmd/envrune/main.go`

**Interfaces:**
- Produces: `executeShell(stdout, stderr io.Writer) int` and a testable `Shell` with injected line reader, password prompt, and `app.OpenSession` factory.
- Produces: `parseShellLine(line string) ([]string, error)` supporting single/double quoted arguments but no expansion or substitution.
- Consumes: `app.Session`, `Presenter`, `runner.Run`, and the existing secure `SecretPrompt` for master/password-value/confirmation reads.

- [ ] **Step 1: Write failing shell tests**

Add tests for one master-password read across two commands, `set` followed by `list`, `exit` cleanup, EOF cleanup, `lock` cleanup, and a malformed quoted line. Assert only safe names/outcomes appear, the secret sentinel never appears, and no command runs after locking.

- [ ] **Step 2: Run shell tests to verify they fail**

Run: `go test ./internal/cli -run TestShell -count=1`

Expected: FAIL because the shell parser and executor do not exist.

- [ ] **Step 3: Implement the shell and session-aware dispatcher**

Route `envrune shell` before the one-shot password path. Read the master password once, open `app.Session`, wipe the password immediately, and defer session close. Print the colored unlocked prompt and read commands until `exit`, `lock`, EOF, or interrupt. Dispatch supported commands through the session without reopening the vault; use existing secure prompts for a new secret value and export/import confirmations. Parse command words without invoking a shell. Keep `init` outside an unlocked session.

- [ ] **Step 4: Run shell and full CLI tests**

Run: `go test ./internal/cli -count=1`

Expected: PASS.

- [ ] **Step 5: Commit the interactive shell**

```bash
git add internal/cli/shell.go internal/cli/shell_test.go internal/cli/command.go internal/cli/prompt.go cmd/envrune/main.go
git commit -m "feat: add one-password interactive shell"
```

### Task 4: Session-aware local UI and visual status polish

**Files:**
- Modify: `internal/app/dashboard.go`
- Modify: `internal/app/dashboard_test.go`
- Modify: `internal/cli/ui.go`
- Modify: `internal/cli/ui_test.go`
- Modify: `web/welcome.html`
- Modify: `web/dashboard.html`
- Modify: `web/locked.html`
- Modify: `web/bootstrap.js`
- Modify: `web/style.css`

**Interfaces:**
- Consumes: `app.Session` as the existing `ui.MetadataSource` interface.
- Produces: a session-aware `executeUIWithSource(source ui.MetadataSource, ...)` path that does not request the master password a second time.

- [ ] **Step 1: Write failing UI session and copy tests**

Add a CLI test which calls the session UI path with a fake metadata source and asserts no password reader is invoked. Extend UI/server tests to ensure rendered assets contain English success/warning/locked state copy and no password/secret sentinel.

- [ ] **Step 2: Run the targeted UI tests to verify they fail**

Run: `go test ./internal/cli ./internal/ui ./internal/app -run '(TestSessionUI|Test.*Dashboard)' -count=1`

Expected: FAIL because the session-aware UI path does not exist.

- [ ] **Step 3: Reuse metadata snapshots and polish UI state styling**

Extract snapshot construction so `Dashboard` and `Session` share it. Let `ui` inside the shell use the session directly; preserve the loopback listener, one-time fragment token, Host/Origin/CSRF checks, and no-store headers. Refine the existing dark CSS with semantic success, warning, error, and locked-status styles; update all visible browser copy to English.

- [ ] **Step 4: Run focused UI tests**

Run: `go test ./internal/app ./internal/cli ./internal/ui -count=1`

Expected: PASS.

- [ ] **Step 5: Commit the session UI integration**

```bash
git add internal/app/dashboard.go internal/app/dashboard_test.go internal/cli/ui.go internal/cli/ui_test.go internal/ui web
git commit -m "feat: improve session UI feedback"
```

### Task 5: Documentation, compatibility checks, and release binary

**Files:**
- Modify: `README.md`
- Modify: `docs/local-ui.md`

**Interfaces:**
- Consumes: completed shell, presenter, and UI behavior.
- Produces: English usage documentation with one-shot and session-shell examples, plus an updated Linux `bin/envrune` build artifact.

- [ ] **Step 1: Document safe English workflows**

Describe `envrune shell`, `lock`, `exit`, `NO_COLOR`, the one-shot compatibility mode, and the fact that export confirmation remains non-echoing. Do not include real secret values or advise using exported plaintext as a persistent workflow.

- [ ] **Step 2: Run full verification and build Linux binary**

Run: `go test ./...`

Expected: PASS for every package.

Run: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/envrune ./cmd/envrune`

Expected: exit code 0.

- [ ] **Step 3: Commit documentation and verify the worktree**

```bash
git add README.md docs/local-ui.md docs/superpowers/specs/2026-09-28-envrune-session-ux-design.md docs/superpowers/plans/2026-09-28-envrune-session-ux.md
git commit -m "docs: describe interactive shell workflow"
git diff --check
git status --short
```
