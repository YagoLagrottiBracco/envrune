# Envrune Phase 1: Secure Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Deliver the Linux-first encrypted local vault and the envrune init, set, and list commands without exposing secret values.

**Architecture:** A thin CLI calls application services, which use a domain reference type and an encrypted on-disk vault. The vault uses a fixed binary header authenticated as AEAD additional data; all secret records remain inside ciphertext. The command process holds the derived key only while the requested command runs.

**Tech Stack:** Go 1.27, standard-library testing, golang.org/x/crypto (Argon2id and XChaCha20-Poly1305), golang.org/x/sys/unix (Linux file locks), golang.org/x/term (no-echo prompts).

**Spec:** docs/superpowers/specs/2026-09-27-envrune-design.md

## Global Constraints

- Build a single Go binary named envrune; support Linux amd64 first and do not require Node or Python at runtime.
- License all project code under Apache-2.0.
- Store the vault at $XDG_DATA_HOME/envrune/vault.ev1, falling back to ~/.local/share/envrune/vault.ev1.
- Derive the vault key with Argon2id: time=3, memory=65536 KiB, threads=min(4, available CPUs), key length=32 bytes.
- Encrypt the vault with XChaCha20-Poly1305 and authenticate the complete fixed header as AAD.
- Never put values in command arguments, stdout, stderr, logs, errors, envrune.yml, or files other than vault ciphertext.
- Prompt for the master password and secret values without echo; do not implement a daemon or key cache.
- Create vault, lock, and temporary files with mode 0600; directories created by Envrune use 0700.
- Keep this plan limited to init, set, and list. Project YAML, runner, import, export, UI, and remote providers belong to later plans.

## Review Focus

- Wrong password, modified header, and modified ciphertext must all return vault.ErrCannotUnlock without disclosing which check failed; Task 3.
- Sentinel enrune-test-secret-DO-NOT-LEAK must not occur in vault.ev1, captured CLI stdout, or captured CLI stderr; Tasks 3 and 5.
- A second process must not write the same vault while an exclusive .lock is held; Task 3.
- Init must not replace an existing vault, and set must not leave a truncated vault after failed replacement; Task 3.
- Commands requiring secrets must fail closed when input is not a terminal; Task 5.

---

## File Structure

    cmd/envrune/main.go                     process entry point and exit status
    internal/paths/data.go                  XDG data path resolution
    internal/domain/reference.go            secret-reference validation
    internal/crypto/params.go               KDF defaults and validation
    internal/crypto/aead.go                 key derivation and authenticated encryption
    internal/vault/errors.go                stable, value-free public errors
    internal/vault/format.go                fixed ev1 header marshal and parse
    internal/vault/lock_linux.go            Linux advisory exclusive lock
    internal/vault/store.go                 opened-vault API and encrypted payload
    internal/app/vault_service.go           init, set, and list use cases
    internal/cli/prompt.go                  terminal-only no-echo input
    internal/cli/command.go                 command dispatch and safe user messages
    internal/*/*_test.go                    focused unit/integration tests
    .gitignore, LICENSE, README.md, go.mod, go.sum

### Task 1: Establish the Go module and safe scaffold

**Files:**
- Create: .gitignore
- Create: LICENSE
- Create: go.mod
- Create: cmd/envrune/main.go
- Create: internal/paths/data.go
- Test: internal/paths/data_test.go
- Create: README.md

**Interfaces:**
- Produces: paths.VaultPath(getenv func(string) string, homeDir func() (string, error)) (string, error).
- Produces: a buildable envrune usage command until Task 5 wires the complete CLI.

- [ ] **Step 1: Initialize Git and module github.com/envrune/envrune with go 1.27**

Add the full Apache-2.0 text. Ignore bin/, .env, and .env.* while explicitly retaining .env.example. Document Linux amd64 and the local threat-model limit in README.

- [ ] **Step 2: Write failing XDG path tests**

    func TestVaultPathUsesXDGDataHome(t *testing.T) {
        got, err := VaultPath(func(string) string { return "/tmp/data" },
            func() (string, error) { return "/home/alice", nil })
        if err != nil || got != "/tmp/data/envrune/vault.ev1" {
            t.Fatalf("got %q, %v", got, err)
        }
    }

    func TestVaultPathFallsBackToHomeDataDirectory(t *testing.T) {
        // expect /home/alice/.local/share/envrune/vault.ev1
    }

- [ ] **Step 3: Run the path tests and verify failure**

Run: go test ./internal/paths -run TestVaultPath -count=1
Expected: FAIL because VaultPath does not exist.

- [ ] **Step 4: Implement paths.VaultPath**

Use only injected environment and home resolvers. Do not create directories in this function.

- [ ] **Step 5: Add dependencies and verify scaffold**

Run: go get golang.org/x/crypto golang.org/x/sys golang.org/x/term; go mod tidy; go test ./...; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/envrune ./cmd/envrune
Expected: tests PASS and bin/envrune is a Linux amd64 binary.

- [ ] **Step 6: Commit**

Run: git add .gitignore LICENSE README.md go.mod go.sum cmd/envrune/main.go internal/paths && git commit -m "chore: bootstrap envrune Go module"

### Task 2: Define reference validation and crypto primitives

**Files:**
- Create: internal/domain/reference.go
- Test: internal/domain/reference_test.go
- Create: internal/crypto/params.go
- Test: internal/crypto/params_test.go
- Create: internal/crypto/aead.go
- Test: internal/crypto/aead_test.go

**Interfaces:**
- Produces: domain.ParseReference(raw string) (domain.Reference, error) and domain.Reference.String() string.
- Produces: crypto.DefaultKDFParams(cpuCount int) crypto.KDFParams.
- Produces: crypto.DeriveKey(password, salt []byte, params crypto.KDFParams) ([]byte, error).
- Produces: crypto.Seal(key, nonce, plaintext, aad []byte) ([]byte, error) and crypto.Open(key, nonce, ciphertext, aad []byte) ([]byte, error).

- [ ] **Step 1: Write failing reference tests**

    func TestParseReferenceAcceptsDotSeparatedLowercaseSegments(t *testing.T) {
        got, err := ParseReference("openai.personal")
        if err != nil || got.String() != "openai.personal" {
            t.Fatalf("got %q, %v", got, err)
        }
    }

    func TestParseReferenceRejectsUnsafeForms(t *testing.T) {
        // reject OpenAI.personal, openai..personal, openai/personal, and empty string
    }

- [ ] **Step 2: Run reference tests and verify failure**

Run: go test ./internal/domain -count=1
Expected: FAIL because ParseReference does not exist.

- [ ] **Step 3: Implement domain.Reference**

Accept exactly ^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$ with a 128-byte maximum. Return a value-free validation error.

- [ ] **Step 4: Write failing KDF and AEAD tests**

    func TestDefaultKDFParamsUsesSecondRFC9106Profile(t *testing.T) {
        // time 3, memory 65536, key length 32, threads capped at 4
    }

    func TestOpenRejectsModifiedAAD(t *testing.T) {
        key := bytes.Repeat([]byte{1}, 32)
        nonce := bytes.Repeat([]byte{2}, 24)
        ciphertext, _ := Seal(key, nonce, []byte("payload"), []byte("header-a"))
        if _, err := Open(key, nonce, ciphertext, []byte("header-b")); err == nil {
            t.Fatal("expected authentication failure")
        }
    }

- [ ] **Step 5: Run crypto tests and verify failure**

Run: go test ./internal/crypto -count=1
Expected: FAIL because KDF and AEAD interfaces do not exist.

- [ ] **Step 6: Implement crypto.KDFParams, DeriveKey, Seal, and Open**

Use argon2.IDKey, chacha20poly1305.NewX, and crypto/rand only. Validate 32-byte salt, 24-byte nonce, 32-byte key, and positive costs. Clear mutable password/key buffers after their last owned use.

- [ ] **Step 7: Verify and commit**

Run: go test ./internal/domain ./internal/crypto -count=1
Expected: PASS.
Run: git add internal/domain internal/crypto && git commit -m "feat: add reference validation and vault crypto"

### Task 3: Implement the authenticated ev1 vault format and durable storage

**Files:**
- Create: internal/vault/errors.go
- Create: internal/vault/format.go
- Test: internal/vault/format_test.go
- Create: internal/vault/lock_linux.go
- Test: internal/vault/lock_linux_test.go
- Create: internal/vault/store.go
- Test: internal/vault/store_test.go

**Interfaces:**
- Consumes: crypto.KDFParams, crypto.DeriveKey, crypto.Seal, crypto.Open, and domain.Reference.
- Produces: vault.Create(path string, password []byte, params crypto.KDFParams) error.
- Produces: vault.Open(path string, password []byte) (*vault.Opened, error).
- Produces: (*Opened).Put(ref domain.Reference, value []byte, now time.Time) error; References() []domain.Reference; Commit() error; Close().
- Produces: vault.ErrAlreadyExists, vault.ErrNotFound, and vault.ErrCannotUnlock.

- [ ] **Step 1: Write failing fixed-header tests**

    func TestHeaderRoundTripPreservesAuthenticatedBytes(t *testing.T) {
        header := Header{Params: crypto.DefaultKDFParams(4),
            Salt: bytes.Repeat([]byte{1}, 32), Nonce: bytes.Repeat([]byte{2}, 24)}
        raw := header.MarshalBinary()
        parsed, err := ParseHeader(raw)
        if err != nil || !bytes.Equal(parsed.MarshalBinary(), raw) {
            t.Fatal("header did not round-trip")
        }
    }

    func TestParseHeaderRejectsWrongMagicAndShortInput(t *testing.T) {
        // expect ErrCannotUnlock
    }

- [ ] **Step 2: Run header tests and verify failure**

Run: go test ./internal/vault -run TestHeader -count=1
Expected: FAIL because Header and ParseHeader do not exist.

- [ ] **Step 3: Implement the exact ev1 fixed header**

Encode in big endian: magic ENVRUNE1 (8 bytes), format version uint16 1, KDF id byte 1, time uint32, memory KiB uint32, threads byte, salt (32 bytes), nonce (24 bytes). Header.MarshalBinary is the only AAD encoding. Reject every malformed header with ErrCannotUnlock.

- [ ] **Step 4: Write failing vault lifecycle and no-plaintext tests**

    func TestVaultRoundTripKeepsSentinelOutOfCiphertext(t *testing.T) {
        const sentinel = "enrune-test-secret-DO-NOT-LEAK"
        path := filepath.Join(t.TempDir(), "vault.ev1")
        mustCreateOpenPutCommit(t, path, []byte("correct horse battery staple"),
            "openai.personal", sentinel)
        raw, _ := os.ReadFile(path)
        if bytes.Contains(raw, []byte(sentinel)) {
            t.Fatal("plaintext leaked to vault file")
        }
    }

    func TestWrongPasswordHeaderTamperAndCiphertextTamperReturnSameError(t *testing.T) {
        // each errors.Is(err, ErrCannotUnlock)
    }

- [ ] **Step 5: Run lifecycle tests and verify failure**

Run: go test ./internal/vault -run 'TestVaultRoundTrip|TestWrongPassword' -count=1
Expected: FAIL because Create and Open do not exist.

- [ ] **Step 6: Implement opened vault and encrypted payload**

The private payload has schema version, secret records keyed by Reference, a project registry, and local operation history; Phase 1 leaves the latter two collections empty but preserves them through reads and writes. Use fresh random salt and nonce at creation and fresh nonce on every Commit. Read no more than 16 MiB before parsing. Convert all parse, decryption, and authentication failures to ErrCannotUnlock.

- [ ] **Step 7: Implement lock and atomic persistence, then add its tests**

Use a sibling .lock file with 0600 and unix.Flock(fd, LOCK_EX|LOCK_NB). Create a 0600 temporary sibling, write ciphertext, Sync it, rename over the target, and sync the parent directory. Test ErrAlreadyExists, lock contention, vault mode 0600, and preservation of the prior decryptable vault after an injected write/rename error.

- [ ] **Step 8: Verify and commit**

Run: go test -race ./internal/vault -count=1
Expected: PASS on Linux.
Run: git add internal/vault && git commit -m "feat: add encrypted durable vault storage"

### Task 4: Add init, set, and list application services

**Files:**
- Create: internal/app/vault_service.go
- Test: internal/app/vault_service_test.go

**Interfaces:**
- Consumes: paths.VaultPath, domain.ParseReference, vault.Create, and vault.Open.
- Produces: app.VaultService.Init(path string, password, confirmation []byte) error.
- Produces: app.VaultService.Set(path string, password []byte, rawReference string, value []byte) error.
- Produces: app.VaultService.List(path string, password []byte) ([]string, error).

- [ ] **Step 1: Write failing service tests**

    func TestSetAndListReturnOnlySortedReferences(t *testing.T) {
        // initialize, set zeta.personal and openai.personal
        // expect []string{"openai.personal", "zeta.personal"}
    }

    func TestSetNeverPlacesValueInReturnedError(t *testing.T) {
        // assert a sentinel is absent from err.Error()
    }

- [ ] **Step 2: Run service tests and verify failure**

Run: go test ./internal/app -count=1
Expected: FAIL because VaultService does not exist.

- [ ] **Step 3: Implement VaultService**

Require password and confirmation equality for Init. Delegate reference validation and persistence. Set copies its value before cleanup, commits once, and closes Opened on every path. List returns sorted references only.

- [ ] **Step 4: Verify and commit**

Run: go test ./internal/app -count=1
Expected: PASS.
Run: git add internal/app && git commit -m "feat: add vault application services"

### Task 5: Build the terminal-only CLI

**Files:**
- Create: internal/cli/prompt.go
- Test: internal/cli/prompt_test.go
- Create: internal/cli/command.go
- Test: internal/cli/command_test.go
- Modify: cmd/envrune/main.go

**Interfaces:**
- Consumes: app.VaultService and paths.VaultPath.
- Produces: cli.Execute(args []string, stdout, stderr io.Writer) int.
- Produces: cli.SecretPrompt.Read(label string) ([]byte, error).

- [ ] **Step 1: Write failing prompt policy test**

    func TestSecretPromptRejectsNonTerminalInput(t *testing.T) {
        prompt := SecretPrompt{IsTerminal: func(int) bool { return false }}
        if _, err := prompt.Read("Master password"); err == nil {
            t.Fatal("expected terminal-only error")
        }
    }

- [ ] **Step 2: Run prompt tests and verify failure**

Run: go test ./internal/cli -run TestSecretPrompt -count=1
Expected: FAIL because SecretPrompt does not exist.

- [ ] **Step 3: Implement terminal-only SecretPrompt**

Write labels to the terminal output, require term.IsTerminal, call term.ReadPassword, append a newline, and trim only the terminal newline. Return a mutable byte slice. Errors say only that secure interactive input is required.

- [ ] **Step 4: Write failing black-box command tests**

    func TestListNeverPrintsSecretValue(t *testing.T) {
        const sentinel = "enrune-test-secret-DO-NOT-LEAK"
        // execute init, set openai.personal, list with scripted prompt values
        // assert sentinel absent from stdout and stderr; reference present in stdout
    }

    func TestSetRejectsValueAsSecondPositionalArgument(t *testing.T) {
        // envrune set openai.personal value must exit nonzero without echoing value
    }

- [ ] **Step 5: Run command tests and verify failure**

Run: go test ./internal/cli -run 'TestListNever|TestSetRejects' -count=1
Expected: FAIL because Execute does not exist.

- [ ] **Step 6: Implement exact Phase 1 grammar**

Accept only envrune init, envrune set <secret-reference>, and envrune list. Init prompts twice; set prompts once for master password and once for the value; list prompts once for master password. Reject positional values, unknown flags, piped secret input, and malformed references without echoing supplied input. Success output may name references and counts but never values.

- [ ] **Step 7: Wire main, verify, and commit**

Run: go test ./internal/cli ./cmd/envrune -count=1 && go vet ./...
Expected: PASS.
Run: git add cmd/envrune internal/cli && git commit -m "feat: add init set and list commands"

### Task 6: Finish Phase 1 security verification

**Files:**
- Modify: README.md
- Modify: internal/vault/store_test.go
- Modify: internal/cli/command_test.go

**Interfaces:**
- Consumes: completed Phase 1 vault and CLI interfaces.
- Produces: repeatable full regression command and safe user documentation.

- [ ] **Step 1: Add named regression tests for every Review Focus item**

Add TestCannotUnlockDoesNotDistinguishFailureKinds, TestVaultFileDoesNotContainSecretSentinel, TestExclusiveLockRejectsConcurrentWriter, TestExistingVaultIsNeverOverwritten, and TestCLIDoesNotAcceptPipedSecrets. Keep them in their owning vault or CLI test package.

- [ ] **Step 2: Run the complete verification suite**

Run: go test -race ./... && go vet ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/envrune ./cmd/envrune
Expected: all tests and vet PASS; bin/envrune is Linux amd64.

- [ ] **Step 3: Document Phase 1 safe usage**

Document init, set, and list without real values. State that a forgotten master password cannot be recovered, secrets have no network behavior in this phase, and root/same-user running-process limits still apply.

- [ ] **Step 4: Re-run verification and commit**

Run: go test -race ./... && go vet ./... && git diff --check
Expected: PASS with no whitespace errors.
Run: git add README.md internal/vault/store_test.go internal/cli/command_test.go && git commit -m "test: harden phase one security regressions"

## Plan Self-Review

- **Spec coverage:** This plan covers the Go/Linux foundation, Apache-2.0, XDG storage, master-password vault, Argon2id/XChaCha20-Poly1305, encrypted metadata, restrictive permissions, atomic writes, locking, init, set, list, non-echo input, and no-leak tests.
- **Intentional deferral:** Project YAML, link, usage, generator, import, run, export, UI, and all remote sync belong to subsequent independent plans after Phase 1 is verified.
- **Type consistency:** domain.Reference enters vault.Opened.Put; vault.Opened enters app.VaultService; app.VaultService enters cli.Execute; KDF and AEAD types stay in internal/crypto.
- **Review Focus:** Each of the five listed failure modes has an owning test in Tasks 3, 5, or 6.
- **Proportion:** The plan is limited to the independently releasable secure core, rather than transcribing the entire project at once.
