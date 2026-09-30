import { accountKey, ApiError, authenticated, base64, body, bytea, fromPostgres, handle, requireInteger, rpc } from "@/lib/api";
import { recipientMessage, verifySignature } from "@/lib/signing";

// POST: a trusted device of the caller certifies one of the caller's
// pending devices, after the user compared fingerprints on both screens.

export const POST = handle(async (request, ctx: RouteContext<"/api/v1/devices/[id]/approve">) => {
  const { id } = await ctx.params;
  const { client, userId } = await authenticated(request);
  const b = await body<{ created_at_us: number; signature: string; account_key_wrapped: string }>(request);
  const createdAt = requireInteger(b.created_at_us, "created_at_us");
  const { data: device, error } = await client.from("devices").select("*").eq("user_id", userId).eq("id", id).maybeSingle();
  if (error) {
    throw fromPostgres(error);
  }
  if (!device) {
    throw new ApiError(404, `no device ${id} on this account`);
  }
  const msg = recipientMessage({ kind: "device", user_id: userId, recipient_id: id, age_recipient: device.age_recipient, signing_key: base64(device.signing_key)!, scope: [], created_at_us: createdAt });
  if (!verifySignature(await accountKey(client, userId), msg, b.signature)) {
    throw new ApiError(400, "the certificate is not signed by your account key");
  }
  await rpc(client, "approve_device", {
    p_id: id,
    p_created_at_us: createdAt,
    p_signature: bytea(b.signature, "signature"),
    p_account_key_wrapped: bytea(b.account_key_wrapped, "account_key_wrapped"),
  });
  return Response.json({ id, approved: true });
});
