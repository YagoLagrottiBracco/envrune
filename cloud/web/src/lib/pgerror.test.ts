import assert from "node:assert/strict";
import { test } from "node:test";
import { answerFor, schemaMissingMessage } from "./pgerror.ts";

test("the schema's own errors keep their status and message", () => {
  assert.deepEqual(answerFor("42501", "only owners may do that"), { status: 403, message: "only owners may do that" });
  assert.deepEqual(answerFor("P0002", "no such project"), { status: 404, message: "no such project" });
});

test("a database without the schema says so, not that the request failed", () => {
  for (const code of ["PGRST205", "PGRST202", "42P01", "42883"]) {
    assert.deepEqual(answerFor(code, "Could not find the table 'public.profiles' in the schema cache"), { status: 503, message: schemaMissingMessage });
  }
});

test("any other error gives its code and keeps its message for the log", () => {
  assert.deepEqual(answerFor("23503", 'Key (org_id)=(1) is not present in table "organizations"'), { status: 500, message: "the request failed (database error 23503)" });
  assert.deepEqual(answerFor(undefined, "fetch failed"), { status: 500, message: "the request failed" });
  assert.deepEqual(answerFor("not a code", "x"), { status: 500, message: "the request failed" });
});
