import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { databaseState, expectedSchema } from "./schema.ts";

// Tests run from cloud/web.
const migrations = join(process.cwd(), "../supabase/migrations");

test("the server expects the newest migration, and that migration says which it is", () => {
  const files = readdirSync(migrations).filter((name) => name.endsWith(".sql")).sort();
  const newest = files[files.length - 1];
  assert.equal(String(expectedSchema), newest.split("_")[0], `schema.ts should expect ${newest}`);
  const sql = readFileSync(join(migrations, newest), "utf8");
  const declared = sql.match(/function public\.schema_version\(\)[\s\S]*?select (\d+)::bigint/);
  assert.ok(declared, `${newest} must redefine public.schema_version()`);
  assert.equal(declared[1], newest.split("_")[0], `${newest} must answer its own number`);
});

test("a database is ok, behind, ahead, or unreachable", () => {
  assert.equal(databaseState({ version: expectedSchema }), "ok");
  assert.equal(databaseState({ version: String(expectedSchema) }), "ok");
  assert.equal(databaseState({ version: expectedSchema - 1 }), "behind");
  assert.equal(databaseState({ missing: true }), "behind");
  assert.equal(databaseState({ version: expectedSchema + 1 }), "ahead");
  assert.equal(databaseState(null), "unreachable");
  assert.equal(databaseState({ version: "nonsense" }), "unreachable");
});
