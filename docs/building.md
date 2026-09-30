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
