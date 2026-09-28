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

This checkout has no tagged binary release. This guide covers the source-build
path only, so it makes no claim about platform coverage beyond the build you
perform yourself. Treat a local `go build` result as a development build from
the exact commit you checked out.
