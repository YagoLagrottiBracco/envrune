"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { findEnvReferences, unlinked, suggestReference } = require("../src/envrefs.js");

test("finds the variables JavaScript and TypeScript read", () => {
  const text = [
    "const a = process.env.DATABASE_URL;",
    "const b = process.env['STRIPE_KEY'];",
    "const c = import.meta.env.VITE_API_URL;",
    "if (process.env.NODE_ENV === 'test') {}",
    "const d = process.env.lowercase;",
  ].join("\n");
  const found = findEnvReferences(text, "typescript");
  assert.deepEqual(found.map((r) => r.name), ["DATABASE_URL", "STRIPE_KEY", "VITE_API_URL", "NODE_ENV"]);
  for (const r of found) {
    assert.equal(text.slice(r.index, r.index + r.length), r.name);
  }
});

test("finds the variables Python reads", () => {
  const text = 'a = os.environ["DATABASE_URL"]\nb = os.environ.get("REDIS_URL", "x")\nc = os.getenv(\'SENTRY_DSN\')\n';
  const found = findEnvReferences(text, "python");
  assert.deepEqual(found.map((r) => r.name), ["DATABASE_URL", "REDIS_URL", "SENTRY_DSN"]);
  assert.equal(text.slice(found[1].index, found[1].index + found[1].length), "REDIS_URL");
});

test("ignores other languages", () => {
  assert.deepEqual(findEnvReferences("process.env.X_Y", "markdown"), []);
});

test("reports only variables no environment links", () => {
  const found = findEnvReferences("process.env.A_KEY; process.env.B_KEY; process.env.NODE_ENV; process.env.C_KEY", "javascript");
  const missing = unlinked(found, new Set(["A_KEY"]), ["C_KEY"]);
  assert.deepEqual(missing.map((r) => r.name), ["B_KEY"]);
});

test("suggests references the way envrune setup does", () => {
  assert.equal(suggestReference("shop", "DATABASE_URL", "development"), "shop.database-url.development");
  assert.equal(suggestReference("My App", "2FA_CODE", "prod"), "my-app.v2fa-code.prod");
});
