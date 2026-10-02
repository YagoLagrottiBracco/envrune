import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { openSensitive, recipientOf } from "./sensitive.ts";

// Written by internal/cloudcrypto's TestSensitiveCrossLanguageVector.
const vector = JSON.parse(readFileSync(new URL("./sensitive-vector.json", import.meta.url), "utf8"));

test("a value sealed by the CLI opens on the server", async () => {
  assert.equal(await recipientOf(vector.identity), vector.recipient);
  const content = await openSensitive(vector.identity, vector.row);
  assert.equal(Buffer.from(content.value).toString("utf8"), vector.value);
  assert.deepEqual(content.hosts, vector.hosts);
});

test("a ciphertext moved to another secret or version does not open", async () => {
  for (const change of [{ name: "other" }, { version: vector.row.version + 1 }, { environment_id: "env-2" }]) {
    await assert.rejects(openSensitive(vector.identity, { ...vector.row, ...change }), /another secret or version/);
  }
});

test("another identity does not open it", async () => {
  const other = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX";
  await assert.rejects(openSensitive(other, vector.row));
});
