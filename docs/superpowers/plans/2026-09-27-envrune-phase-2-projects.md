# Envrune Phase 2: Project Links Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe, versionable project mappings and the `link` and `usage` commands without ever placing secret values in project files or output.

**Architecture:** `internal/project` owns discovery and strict YAML parsing/writing; `internal/app` coordinates project mappings and the encrypted vault; `internal/cli` exposes command grammar and safe messages. Project registration is encrypted metadata in the existing vault, while `usage` re-reads the current `envrune.yml` files so it cannot become stale.

**Tech Stack:** Go 1.27, `gopkg.in/yaml.v3`, standard library tests.

**Spec:** `docs/superpowers/specs/2026-09-27-envrune-design.md`

## Global Constraints

- `envrune.yml` is versionable and never contains values, passwords, ciphertext or generated plaintext.
- Discover from the working directory upward; do not cross the filesystem root.
- Only `VAR: reference` mappings are accepted in each environment; variables use POSIX names and references reuse `domain.ParseReference`.
- `link` atomically updates project YAML and registers the project path only in the encrypted vault.
- `usage` lists project paths, environments and variable names only.
- All parser and CLI errors stay value-free; tests use a sentinel to prove it.

## Review Focus

- A malicious YAML alias, duplicate key or unexpected node type is rejected before it can alter mappings.
- Discovery outside a project returns a stable not-found error and never creates a file.
- `link` preserves unrelated environments and mappings through an atomic rewrite.
- `usage` reflects a project file changed after registration rather than historical copies.
- Sentinel values never occur in YAML, stdout, stderr or returned errors.

---

### Task 1: Strict project configuration and discovery

**Files:** Create `internal/project/config.go`, `internal/project/discovery.go`; test `internal/project/config_test.go`, `internal/project/discovery_test.go`.

**Interfaces:** Produce `project.Config`, `project.Load(path string) (Config, error)`, `project.Find(start string) (path string, error)`, and `project.WriteAtomic(path string, config Config) error`.

- [ ] Write failing tests for a valid multi-environment configuration, invalid variable/reference forms, duplicate keys, unknown YAML structure and upward discovery.
- [ ] Run `go test ./internal/project -count=1`; verify the package is absent.
- [ ] Add `gopkg.in/yaml.v3`; implement node-level parsing that accepts only version 1, a string project name, and string mappings under environments.
- [ ] Implement discovery and a 0600 temporary sibling + sync + rename writer preserving deterministic mapping order.
- [ ] Run `go test ./internal/project -count=1`; commit `feat: add strict project configuration`.

### Task 2: Link and usage application services

**Files:** Modify `internal/vault/store.go`; modify `internal/app/vault_service.go`; test `internal/app/project_service_test.go`.

**Interfaces:** Extend encrypted payload with registered project paths. Produce `VaultService.Link(vaultPath, projectPath, environment, variable, reference string, password []byte) error` and `VaultService.Usage(vaultPath, reference string, password []byte) ([]Usage, error)`.

- [ ] Write failing tests that link a mapping, retain existing YAML mappings, and report sorted current usage after a manual YAML modification.
- [ ] Run `go test ./internal/app -run 'TestLink|TestUsage' -count=1`; verify failure.
- [ ] Add vault methods for registering and listing project paths; preserve registrations through encrypted commits without exposing them in errors.
- [ ] Implement Link with reference/variable validation, atomic config write, and encrypted registration only after a successful project write.
- [ ] Implement Usage by loading each registered current config and returning sorted metadata; skip unavailable paths without leaking filesystem details.
- [ ] Run `go test ./internal/app ./internal/vault -count=1`; commit `feat: add project link and usage services`.

### Task 3: CLI grammar for project commands

**Files:** Modify `internal/cli/command.go`; test `internal/cli/command_test.go`; modify `cmd/envrune/main.go` only if dependency injection needs wiring.

**Interfaces:** Extend `cli.Execute(args []string, stdout, stderr io.Writer) int` with `link <VAR> <reference> --env <environment>` and `usage <reference>`.

- [ ] Write failing black-box tests for accepted link syntax, rejected missing/extra flags, safe usage output and a sentinel absent from both output streams.
- [ ] Run `go test ./internal/cli -run 'TestLink|TestUsage' -count=1`; verify failure.
- [ ] Implement exact argument parsing with no shell expansion; obtain vault path and interactive password through existing safe services.
- [ ] Print only reference, variable, environment and project metadata; map all failures to safe human messages.
- [ ] Run `go test ./internal/cli ./cmd/envrune -count=1 && go vet ./...`; commit `feat: add project link and usage commands`.

### Task 4: Phase 2 regression verification and documentation

**Files:** Modify `README.md`; test `internal/project/config_test.go`, `internal/app/project_service_test.go`, `internal/cli/command_test.go`.

- [ ] Add named regressions for atomic YAML preservation, malformed YAML rejection, stale-usage avoidance and sentinel non-leakage.
- [ ] Document `envrune.yml`, `link`, and `usage` with references only; explicitly state that project YAML contains no values.
- [ ] Run `go test ./... && go vet ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/envrune ./cmd/envrune`; inspect `git diff --check`.
- [ ] Commit `test: harden phase two project regressions`.

## Self-review

- Config parsing, discovery, atomic rewriting, encrypted registration, commands and no-leak tests each have an owning task.
- Task 2 consumes the Phase 1 vault and domain interfaces; Task 3 consumes only Task 2 services.
- YAML parsing is deliberately strict; import, process execution, export and UI remain Phase 3/4 work.
