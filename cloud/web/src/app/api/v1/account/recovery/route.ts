import { ApiError, accountKey, authenticated, body, bytea, handle, requireInteger, requireString, rpc } from "@/lib/api";
import { recipientMessage, verifySignature } from "@/lib/signing";

// POST: replace the caller's recovery backup and recovery recipient, from
// one of their approved devices. The new recipient must be signed by the
// registered account key, so only a device that holds it can do this; the
// keys wrapped for the old recipient are deleted.

interface Reset {
  device_id: string;
  recovery_backup: string;
  recovery: { age_recipient: string; created_at_us: number; signature: string };
}

export const POST = handle(async (request) => {
  const { client, userId } = await authenticated(request);
  const b = await body<Reset>(request);
  const device = requireString(b.device_id, "device_id", 64);
  requireString(b.recovery_backup, "recovery_backup", 4096);
  const recipient = requireString(b.recovery?.age_recipient, "recovery.age_recipient");
  const createdAt = requireInteger(b.recovery?.created_at_us, "recovery.created_at_us");
  const signature = requireString(b.recovery?.signature, "recovery.signature");
  const msg = recipientMessage({ kind: "recovery", user_id: userId, recipient_id: "recovery", age_recipient: recipient, signing_key: "", scope: [], created_at_us: createdAt });
  if (!verifySignature(await accountKey(client, userId), msg, signature)) {
    throw new ApiError(400, "the recovery recipient is not signed by the account key");
  }
  await rpc(client, "reset_recovery", {
    p_recovery_backup: bytea(b.recovery_backup, "recovery_backup"),
    p_recovery_recipient: recipient,
    p_recovery_created_at_us: createdAt,
    p_recovery_signature: bytea(signature, "recovery.signature"),
    p_device: device,
  });
  return new Response(null, { status: 204 });
});
