import { accountKey, ApiError, authenticated, body, bytea, handle, requireInteger, requireString, rpc } from "@/lib/api";
import { recipientMessage, verifySignature } from "@/lib/signing";

// POST: register a device of the caller. Without a signature it waits for a
// trusted device to approve it; with one, the account key certified it
// (after recovery).

interface NewDevice {
  id: string;
  name?: string;
  age_recipient: string;
  signing_key: string;
  created_at_us: number;
  signature?: string;
}

export const POST = handle(async (request) => {
  const { client, userId } = await authenticated(request);
  const b = await body<NewDevice>(request);
  const id = requireString(b.id, "id", 64);
  const recipient = requireString(b.age_recipient, "age_recipient");
  requireString(b.signing_key, "signing_key");
  const createdAt = requireInteger(b.created_at_us, "created_at_us");
  if (b.signature) {
    const msg = recipientMessage({ kind: "device", user_id: userId, recipient_id: id, age_recipient: recipient, signing_key: b.signing_key, scope: [], created_at_us: createdAt });
    if (!verifySignature(await accountKey(client, userId), msg, b.signature)) {
      throw new ApiError(400, "the device certificate is not signed by your account key");
    }
  }
  await rpc(client, "register_device", {
    p_id: id,
    p_name: b.name ?? "",
    p_age_recipient: recipient,
    p_signing_key: bytea(b.signing_key, "signing_key"),
    p_created_at_us: createdAt,
    p_signature: b.signature ? bytea(b.signature, "signature") : null,
  });
  return Response.json({ id, pending: !b.signature }, { status: 201 });
});
