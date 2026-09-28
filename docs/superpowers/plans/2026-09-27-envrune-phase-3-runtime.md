# Envrune Phase 3: Runtime and Interchange Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add secure generation, deliberate import/export, and direct child-process execution using project references without writing secrets to temporary environment files.

**Architecture:** `internal/generator` creates values with `crypto/rand`; `internal/project` parses only the restricted dotenv interchange format; `internal/app` resolves values from the vault and coordinates confirmation-free data transforms; `internal/runner` starts a direct child process with an extended environment. The CLI retains terminal-only secret input and prints names, counts, warnings and safe outcomes—never values.

**Tech Stack:** Go 1.27, standard library (`crypto/rand`, `os/exec`, `os/signal`), existing Argon2id/XChaCha20 vault and project packages, `golang.org/x/sys/unix` for Linux child hardening.

**Spec:** `docs/superpowers/specs/2026-09-27-envrune-design.md`

## Global Constraints

- No secret appears in arguments, stdout, stderr, errors, logs, YAML or temporary `.env` files.
- `generate` uses CSPRNG, stores the new value directly in the encrypted vault, and accepts a bounded explicit length.
- `import` reads a user-selected dotenv file, reports only detected variable names, never deletes its source and only stores values after an interactive confirmation.
- `run` resolves mappings for one environment and uses `exec.Cmd` directly—never a shell or temporary file.
- On Linux, the child applies `PR_SET_DUMPABLE=0` immediately before `exec` on a best-effort basis; unavailable hardening emits a safe warning only.
- `export` is deliberate: output defaults to `./.env.<environment>`, mode 0600, refuses overwrite without `--force`, confirms its plaintext risk, and never removes the file automatically.
- A destination inside a Git worktree requires an additional confirmation; output errors are value-free.

## Review Focus

- A sentinel value is absent from captured CLI stdout/stderr, YAML, import diagnostics and runner errors.
- `run` rejects a missing project/environment/reference before spawning any child, and does not invoke a shell.
- The child receives only mappings for the selected environment while preserving unrelated parent environment entries.
- Malformed dotenv lines, duplicates, unsupported quoting and empty names are rejected before any vault change.
- Export cannot overwrite an existing file without `--force`, and its permissions are 0600 on Linux.

---

### Task 1: Secure generator and restricted dotenv parser

**Files:** Create `internal/generator/value.go`, `internal/generator/value_test.go`, `internal/dotenv/parser.go`, `internal/dotenv/parser_test.go`.

**Interfaces:** Produce `generator.New(length int) ([]byte, error)` and `dotenv.Parse(raw []byte) ([]dotenv.Entry, error)` where `Entry` contains only a POSIX variable name and mutable value bytes.

- [ ] Write failing tests for length boundaries, randomized outputs, accepted `NAME=value` lines, comments/blank lines, and rejection of duplicate names, `export`, quotes, multiline data and malformed lines.
- [ ] Run `go test ./internal/generator ./internal/dotenv -count=1`; verify the packages are absent.
- [ ] Implement CSPRNG generation using an unambiguous URL-safe alphabet and restricted dotenv parsing that makes no environment mutation.
- [ ] Run the focused tests; commit `feat: add secure generator and dotenv parser`.

### Task 2: Runtime application services

**Files:** Modify `internal/vault/store.go`; modify `internal/app/vault_service.go`; test `internal/app/runtime_service_test.go`.

**Interfaces:** Extend `Opened` with value-safe retrieval used only by app services. Produce `VaultService.Generate(path, reference string, length int, password []byte) error`, `VaultService.Import(path string, entries []dotenv.Entry, password []byte) (count int, error)`, `VaultService.ResolveEnvironment(vaultPath, projectPath, environment string, password []byte) ([]runner.Pair, error)` and `VaultService.Export(...)` returning plaintext only to the immediate output writer abstraction.

- [ ] Write failing tests for generation storage, import atomicity on invalid input, missing references, selected-environment resolution and sentinel absence from returned errors.
- [ ] Run focused app/vault tests; verify failure.
- [ ] Add an internal-only vault value lookup, never exposed by list/usage/UI paths. Coordinate every vault change with a single commit and zero temporary plaintext files.
- [ ] Implement app operations with validation before mutation; return only counts/names/value-free errors.
- [ ] Run `go test ./internal/app ./internal/vault -count=1`; commit `feat: add runtime application services`.

### Task 3: Direct Linux runner and CLI commands

**Files:** Create `internal/runner/run.go`, `internal/runner/run_linux.go`, `internal/runner/run_other.go`, `internal/runner/run_test.go`; modify `internal/cli/command.go`, `internal/cli/command_test.go`; modify `cmd/envrune/main.go` only as needed.

**Interfaces:** Produce `runner.Run(command []string, additions []Pair, inherited []string, stdout, stderr io.Writer) (exitCode int, err error)` and extend `cli.Execute` with `generate`, `import`, `run --env <environment> -- <command>`, and `export --env <environment> [--output path] [--force]`.

- [ ] Write failing runner tests for direct argv execution, injected selected values, nonzero exit propagation and no `.env` file creation; write CLI tests that reject positional values and piped confirmation/password input.
- [ ] Run the focused tests and verify failure.
- [ ] Implement `exec.Command` with explicit `Cmd.Env`, process-group/signal forwarding where supported, and Linux `PR_SET_DUMPABLE` best effort in the child setup path.
- [ ] Implement exact command grammar: terminal confirmation before import/export, names-only previews, and safe status/error messages.
- [ ] Run `go test ./internal/runner ./internal/cli ./cmd/envrune -count=1`; commit `feat: add secure runtime commands`.

### Task 4: Export durability and Phase 3 security regression

**Files:** Create `internal/exporter/write.go`, `internal/exporter/write_test.go`; modify `README.md`; extend app/CLI/runner tests.

**Interfaces:** Produce `exporter.Write(path string, variables []runner.Pair, force bool) error` with atomic 0600 output and overwrite refusal.

- [ ] Write failing tests for default caller-provided path, overwrite refusal, force replacement, deterministic dotenv rendering, mode 0600 and sentinel non-leakage outside the requested output file.
- [ ] Run exporter tests and verify failure.
- [ ] Implement same-directory temporary output, sync, rename and parent sync; keep plaintext confined to the requested destination.
- [ ] Add named end-to-end regressions for `run` no-file behavior, import confirmation, export Git-destination extra confirmation, and all sentinel non-leak contexts.
- [ ] Document safe command use, residual process-environment risk, and the manual deletion obligation for exports.
- [ ] Run `go test ./... && go vet ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/envrune ./cmd/envrune`; inspect `git diff --check`; commit `test: harden phase three runtime security`.

## Self-review

- Generation, parsing, vault resolution, direct execution and plaintext export are separate testable units with no UI/provider scope added.
- Only Task 2 may access secret values after vault decryption; Task 3 receives short-lived pairs and Task 4 receives them only for the explicitly requested destination.
- Every plaintext boundary has a dedicated no-leak or permissions regression; all Phase 3 command grammar is owned by Task 3.
