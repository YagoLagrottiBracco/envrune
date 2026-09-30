import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { memberMessage, recipientMessage, verifySignature, type MemberFields, type RecipientFields } from "./signing.ts";

// Written by internal/cloudcrypto's TestCrossLanguageVectors.
const vectors = JSON.parse(readFileSync(new URL("./crypto-vectors.json", import.meta.url), "utf8"));

test("messages match the Go encoding byte for byte", () => {
  for (const v of vectors.filter((x: { kind: string }) => x.kind !== "token-secret")) {
    const msg = v.kind === "member" ? memberMessage(v.fields as MemberFields) : recipientMessage(v.fields as RecipientFields);
    assert.equal(Buffer.from(msg).toString("base64"), v.message, `${v.kind} ${v.fields.recipient_id ?? v.fields.user_id}`);
  }
});

test("signatures made in Go verify here", () => {
  for (const v of vectors.filter((x: { kind: string }) => x.kind !== "token-secret")) {
    const msg = v.kind === "member" ? memberMessage(v.fields) : recipientMessage(v.fields);
    assert.ok(verifySignature(v.public_key, msg, v.signature));
  }
});

test("a changed field or a wrong key fails", () => {
  const v = vectors[0];
  assert.ok(!verifySignature(v.public_key, memberMessage({ ...v.fields, role: "owner" }), v.signature));
  assert.ok(!verifySignature(Buffer.alloc(32, 9).toString("base64"), memberMessage(v.fields), v.signature));
  assert.ok(!verifySignature("short", memberMessage(v.fields), v.signature));
});

test("machine token secrets hash as in Go", async () => {
  const { tokenSecretHash, tokenSecretMatches, fromBase64 } = await import("./signing.ts");
  const v = vectors.find((x: { kind: string }) => x.kind === "token-secret");
  const secret = fromBase64(v.fields.secret);
  assert.equal(tokenSecretHash(secret).toString("base64"), v.message);
  assert.ok(tokenSecretMatches(secret, fromBase64(v.message)));
  assert.ok(!tokenSecretMatches(new Uint8Array(32), fromBase64(v.message)));
});
