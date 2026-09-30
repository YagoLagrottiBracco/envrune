# Building EnvRune

This repository is the canonical source while EnvRune is pre-release. A local
build needs Go 1.27.

## Verify the checkout

From the repository root, run the test suite:

```sh
go test ./...
```

The tests cover vault behavior, configuration parsing, runtime handling, and
the local UI. A passing test suite is the baseline before producing a binary.

The CLI integration tests build `envrune` and run it the way a user does: a
real vault, child processes found on `PATH`, several `envrune` processes at
once, and `envrune up` stopping every process it started. They take about
20 seconds:

```sh
go test -tags integration ./test/integration
```

To run them where Go is not installed, such as a VM, cross-compile the test
binary together with `envrune` and the probe it starts, then point
`ENVRUNE_IT_BIN` at the folder that holds all three:

```sh
GOOS=linux go build -o it/envrune ./cmd/envrune
GOOS=linux go build -o it/probe ./test/integration/testdata/probe
GOOS=linux go test -c -tags integration -o it/it.test ./test/integration
# on the target machine
ENVRUNE_IT_BIN=$PWD/it ./it/it.test -test.v
```

The `ci` GitHub Actions workflow runs `go vet`, the unit tests, and the
integration tests on Linux, macOS, and Windows for every push and pull
request, and checks that other targets still compile.

EnvRune Cloud has two more suites. With Docker running, from the repository
root:

```sh
(cd cloud && npx supabase start && npx supabase test db)   # database access rules
cloud/e2e.sh   # the CLI's client against the API and the database, all local
```

`cloud/e2e.sh` builds the API in `cloud/web`, starts it next to a local
Supabase, and runs `go test -tags e2e ./internal/cloud`. CI runs both.

## Build a local binary

```sh
go build -trimpath -o bin/envrune ./cmd/envrune
./bin/envrune --help
```

`-trimpath` removes local source paths from the compiled output. The `bin/`
directory is ignored by Git, so a local binary will not appear as an untracked
project change.

## Use a source build

You can keep using the project-local binary:

```sh
./bin/envrune shell
```

Or install a binary into a directory already on your `PATH` using the
conventions of your operating system. The installation destination is a user
choice; EnvRune does not self-install or modify shell startup files.

When the Go binary directory is on your `PATH`, Go can perform that placement:

```sh
go install ./cmd/envrune
envrune --help
```

## Release status

Tagged binary releases are produced by GoReleaser (`.goreleaser.yaml`) in the
`release` GitHub Actions workflow whenever a `v*` tag is pushed. The workflow
runs `go test ./...`, cross-compiles for Linux, macOS, and Windows on amd64 and
arm64, and builds the installers: `.deb` and `.rpm` packages, a universal
macOS `.pkg`, and a Windows setup `.exe` (Inno Setup, from
`packaging/windows/envrune.iss`). It then regenerates `checksums.txt` over
every asset, publishes the release, and marks it as the latest.
Treat a local `go build` result as a development build from the exact commit
you checked out.
