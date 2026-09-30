import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { load, EnvruneError } from "../index.js";

// A stand-in for the envrune CLI: a shell script, so these tests run where
// /bin/sh exists (Linux and macOS in CI).
function fakeEnvrune(body) {
  const dir = mkdtempSync(join(tmpdir(), "envrune-node-"));
  const path = join(dir, "envrune");
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
  return path;
}

const posix = process.platform !== "win32";

test("load sets variables and keeps ones already set", { skip: !posix }, () => {
  const binary = fakeEnvrune(`printf '%s\\n' '{"ENVRUNE_T_A":"from vault","ENVRUNE_T_B":"x\\ny"}'`);
  process.env.ENVRUNE_T_A = "already set";
  delete process.env.ENVRUNE_T_B;
  const values = load({ binary, env: "staging" });
  assert.equal(values.ENVRUNE_T_A, "from vault");
  assert.equal(process.env.ENVRUNE_T_A, "already set");
  assert.equal(process.env.ENVRUNE_T_B, "x\ny");
  load({ binary, override: true });
  assert.equal(process.env.ENVRUNE_T_A, "from vault");
});

test("load passes the environment and never prompts", { skip: !posix }, () => {
  const binary = fakeEnvrune(`echo '{}'; echo "$@" >&2; [ "$*" = "env --format json --no-prompt --env staging" ] || exit 9`);
  assert.doesNotThrow(() => load({ binary, env: "staging" }));
});

test("a locked vault is an error with EnvRune's message", { skip: !posix }, () => {
  const binary = fakeEnvrune(`echo '[ERROR] The vault is locked. Run \`envrune unlock\` first.' >&2; exit 1`);
  assert.throws(() => load({ binary }), (error) => error instanceof EnvruneError && error.message === "The vault is locked. Run `envrune unlock` first.");
});

test("a missing binary says how to fix it", () => {
  assert.throws(() => load({ binary: join(tmpdir(), "no-such-envrune-binary") }), (error) => error instanceof EnvruneError && /not found/.test(error.message));
});
