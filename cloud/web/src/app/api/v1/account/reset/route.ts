import { ApiError, authenticated, body, bytea, handle, requireInteger, requireString, rpc } from "@/lib/api";
import { recipientMessage, verifySignature } from "@/lib/signing";

// POST: replace the caller's account key, with a new recovery backup and
// recipient and one new device, all certified by the new key. The database
// allows it only for an account that is in no organization and is no
// organization's root holder; see docs/cloud-crypto.md.

interface Reset {
  account_key: string;
  recovery_backup: string;
  recovery: { age_recipient: string; created_at_us: number; signature: string };
  device: { id: string; name: string; age_recipient: string; signing_key: string; created_at_us: number; signature: string };
}

export const POST = handle(async (request) => {
  const { client, userId } = await authenticated(request);
  const b = await body<Reset>(request);
  const accountKey = requireString(b.account_key, "account_key");
  requireString(b.recovery_backup, "recovery_backup", 4096);
  const recipient = requireString(b.recovery?.age_recipient, "recovery.age_recipient");
  const recoveryAt = requireInteger(b.recovery?.created_at_us, "recovery.created_at_us");
  const recoverySignature = requireString(b.recovery?.signature, "recovery.signature");
  const deviceId = requireString(b.device?.id, "device.id", 64);
  const deviceName = typeof b.device?.name === "string" ? b.device.name.slice(0, 100) : "";
  const deviceRecipient = requireString(b.device?.age_recipient, "device.age_recipient");
  const deviceSigningKey = requireString(b.device?.signing_key, "device.signing_key");
  const deviceAt = requireInteger(b.device?.created_at_us, "device.created_at_us");
  const deviceSignature = requireString(b.device?.signature, "device.signature");

  // Both must be the new key's: a reset that the new key did not sign would
  // leave an account whose device and recovery nobody can verify.
  const recovery = recipientMessage({ kind: "recovery", user_id: userId, recipient_id: "recovery", age_recipient: recipient, signing_key: "", scope: [], created_at_us: recoveryAt });
  const device = recipientMessage({ kind: "device", user_id: userId, recipient_id: deviceId, age_recipient: deviceRecipient, signing_key: deviceSigningKey, scope: [], created_at_us: deviceAt });
  if (!verifySignature(accountKey, recovery, recoverySignature) || !verifySignature(accountKey, device, deviceSignature)) {
    throw new ApiError(400, "the recovery recipient and the device must be signed by the new account key");
  }
  await rpc(client, "reset_account", {
    p_account_key: bytea(accountKey, "account_key"),
    p_recovery_backup: bytea(b.recovery_backup, "recovery_backup"),
    p_recovery_recipient: recipient,
    p_recovery_created_at_us: recoveryAt,
    p_recovery_signature: bytea(recoverySignature, "recovery.signature"),
    p_device_id: deviceId,
    p_device_name: deviceName,
    p_device_age_recipient: deviceRecipient,
    p_device_signing_key: bytea(deviceSigningKey, "device.signing_key"),
    p_device_created_at_us: deviceAt,
    p_device_signature: bytea(deviceSignature, "device.signature"),
  });
  return new Response(null, { status: 204 });
});
