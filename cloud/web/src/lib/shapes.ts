import { base64 } from "./api";

// Database rows as the CLI receives them: binary fields in base64.

/* eslint-disable @typescript-eslint/no-explicit-any */

/** A device; its wrapped account key only for the device owner (own = true). */
export function deviceJson(d: any, own = false) {
  return {
    ...(own ? { account_key_wrapped: base64(d.account_key_wrapped ?? null) } : {}),
    user_id: d.user_id,
    id: d.id,
    kind: d.kind,
    name: d.name,
    age_recipient: d.age_recipient,
    signing_key: base64(d.signing_key),
    created_at_us: d.created_at_us,
    signature: base64(d.signature),
    revoked_at: d.revoked_at,
  };
}

export function certJson(c: any) {
  return {
    org_id: c.org_id,
    user_id: c.user_id,
    account_key: base64(c.account_key),
    role: c.role,
    scope: c.scope,
    issued_at_us: c.issued_at_us,
    issuer_id: c.issuer_id,
    signature: base64(c.signature),
  };
}

export function tokenJson(t: any) {
  return {
    id: t.id,
    name: t.name,
    created_by: t.created_by,
    age_recipient: t.age_recipient,
    scope: t.scope,
    created_at_us: t.created_at_us,
    signature: base64(t.signature),
    expires_at: t.expires_at,
    revoked_at: t.revoked_at,
    last_used_at: t.last_used_at,
  };
}
