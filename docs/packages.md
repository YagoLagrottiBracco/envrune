# Replacing dotenv in code

When a program loads its settings itself, with `dotenv` in Node or
`python-dotenv` in Python, the `envrune` packages are drop-in replacements
that read from the vault instead of a `.env` file:

```js
// Node, instead of import "dotenv/config"
import "envrune/config";
```

```python
# Python, instead of from dotenv import load_dotenv; load_dotenv()
import envrune
envrune.load()
```

Use them where `envrune run -- <command>` does not fit, such as a debugger or
a test runner started by an editor. With `envrune run`, the variables are
already set and the packages are not needed.

## How they work

Each package runs `envrune env --format json --no-prompt` in the current
folder and sets the variables of the nearest `envrune.yml`, for its default
environment, in `process.env` or `os.environ`. Variables that are already set
are kept, as dotenv does; pass `override` to replace them.

`--no-prompt` means the vault must already be unlocked: run
`envrune unlock --ttl 8h`, turn on `envrune keychain enable`, or set
`ENVRUNE_PASSWORD` in CI. When it is locked, loading fails with EnvRune's
message instead of falling back to a `.env` file:

```text
EnvruneError: The vault is locked. Run `envrune unlock` first.
```

## Options

| Node | Python | Meaning |
| --- | --- | --- |
| `load({ env: "staging" })`, or `ENVRUNE_ENV` with `envrune/config` | `load("staging")` | Load another environment. |
| `load({ cwd })` | `load(cwd=...)` | Look for `envrune.yml` from another folder. |
| `load({ override: true })` | `load(override=True)` | Replace variables that are already set. |
| `load({ binary })`, or `ENVRUNE_BIN` | `load(binary=...)`, or `ENVRUNE_BIN` | Use another `envrune` executable. |

Both return the variables they loaded. Both packages live in
[`packages/`](../packages) and are not yet published to npm or PyPI; install
them from a checkout:

```sh
npm install ./packages/node
pip install ./packages/python
```

## Limits

The values end up in the process environment, where any code in the process
can read them, as with dotenv. Output masking does not apply to a program
that loads its own settings; run it with `envrune run` to mask its output.
