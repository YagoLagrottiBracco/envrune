import { ApiError, authenticated, base64, body, bytea, fromPostgres, handle, requireInteger, requireString, rpc } from "@/lib/api";
import { deviceJson } from "@/lib/shapes";
import { recipientMessage, verifySignature } from "@/lib/signing";

// POST: register the caller's account key, recovery backup, and certified
// recovery recipient. GET: the caller's profile and devices.

interface Registration {
  account_key: string;
  recovery_backup: string;
  recovery: { age_recipient: string; created_at_us: number; signature: string };
}

export const POST = handle(async (request) => {
  const { client, userId } = await authenticated(request);
  const b = await body<Registration>(request);
  requireString(b.account_key, "account_key");
  requireString(b.recovery_backup, "recovery_backup", 4096);
  const recipient = requireString(b.recovery?.age_recipient, "recovery.age_recipient");
  const createdAt = requireInteger(b.recovery?.created_at_us, "recovery.created_at_us");
  const msg = recipientMessage({ kind: "recovery", user_id: userId, recipient_id: "recovery", age_recipient: recipient, signing_key: "", scope: [], created_at_us: createdAt });
  if (!verifySignature(b.account_key, msg, b.recovery.signature)) {
    throw new ApiError(400, "the recovery recipient is not signed by the account key");
  }
  await rpc(client, "register_account", {
    p_account_key: bytea(b.account_key, "account_key"),
    p_recovery_backup: bytea(b.recovery_backup, "recovery_backup"),
    p_recovery_recipient: recipient,
    p_recovery_created_at_us: createdAt,
    p_recovery_signature: bytea(b.recovery.signature, "recovery.signature"),
  });
  return Response.json({ user_id: userId }, { status: 201 });
});

export const GET = handle(async (request) => {
  const { client, userId } = await authenticated(request);
  const profile = await client.from("profiles").select("account_key, recovery_backup").eq("user_id", userId).maybeSingle();
  if (profile.error) {
    throw fromPostgres(profile.error);
  }
  const devices = await client.from("devices").select("*").eq("user_id", userId);
  if (devices.error) {
    throw fromPostgres(devices.error);
  }
  return Response.json({
    user_id: userId,
    registered: profile.data !== null,
    account_key: profile.data ? base64(profile.data.account_key) : null,
    recovery_backup: profile.data ? base64(profile.data.recovery_backup) : null,
    devices: devices.data.map((d) => deviceJson(d, true)),
  });
});
