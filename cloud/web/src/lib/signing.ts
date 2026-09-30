// The signed-message encoding of internal/cloudcrypto, so the API can reject
// certificates whose signatures do not verify before storing them. Clients
// verify every signature again; this check only keeps junk out.
// crypto-vectors.json, written by the Go tests, keeps the two in step.

import { createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";

const utf8 = new TextEncoder();

/** A domain label, then every field, each with a 4-byte big-endian length. */
export function message(label: string, ...fields: Uint8Array[]): Uint8Array {
  const parts = [utf8.encode(label), ...fields];
  const size = parts.reduce((n, p) => n + 4 + p.length, 0);
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let at = 0;
  for (const part of parts) {
    view.setUint32(at, part.length);
    out.set(part, at + 4);
    at += 4 + part.length;
  }
  return out;
}

const str = (s: string) => utf8.encode(s);
const micros = (n: number) => utf8.encode(String(n));
export const fromBase64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));

export interface MemberFields {
  org_id: string;
  user_id: string;
  account_key: string; // base64
  role: string;
  scope: string[];
  issued_at_us: number;
  issuer_id: string;
}

export interface RecipientFields {
  kind: "device" | "recovery" | "machine";
  user_id: string;
  recipient_id: string;
  age_recipient: string;
  signing_key: string; // base64, empty for recovery and machines
  scope: string[];
  created_at_us: number;
}

export function memberMessage(f: MemberFields): Uint8Array {
  return message("envrune-member-v1", str(f.org_id), str(f.user_id), fromBase64(f.account_key), str(f.role),
    str(f.scope.join("\n")), micros(f.issued_at_us), str(f.issuer_id));
}

export function recipientMessage(f: RecipientFields): Uint8Array {
  return message("envrune-recipient-v1", str(f.kind), str(f.user_id), str(f.recipient_id), str(f.age_recipient),
    fromBase64(f.signing_key), str(f.scope.join("\n")), micros(f.created_at_us));
}

/** The hash the server stores for a machine token's secret. */
export function tokenSecretHash(secret: Uint8Array): Buffer {
  return createHash("sha256").update(message("envrune-token-secret-v1", secret)).digest();
}

/** Compares a presented token secret with a stored hash in constant time. */
export function tokenSecretMatches(secret: Uint8Array, stored: Uint8Array): boolean {
  const hash = tokenSecretHash(secret);
  return stored.length === hash.length && timingSafeEqual(hash, stored);
}

// DER prefix of an Ed25519 SubjectPublicKeyInfo, followed by the 32-byte key.
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

/** Verifies an Ed25519 signature; keys and signatures are base64. */
export function verifySignature(publicKey: string, msg: Uint8Array, signature: string): boolean {
  const raw = Buffer.from(publicKey, "base64");
  const sig = Buffer.from(signature, "base64");
  if (raw.length !== 32 || sig.length !== 64) {
    return false;
  }
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, raw]), format: "der", type: "spki" });
  return verify(null, msg, key, sig);
}
