import { accountKey, ApiError, authenticated, body, bytea, handle, orgBySlug, requireInteger, requireString, requireStrings, rpc } from "@/lib/api";
import { recipientMessage, verifySignature } from "@/lib/signing";

// POST: register a machine token created on the admin's machine. Only the
// token's public recipient, its certificate, and a hash of its API secret
// reach the server; the CI system holds the rest.

interface Token {
  id: string;
  name?: string;
  age_recipient: string;
  scope: string[];
  created_at_us: number;
  signature: string;
  secret_hash: string;
  expires_at: string;
}

export const POST = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/tokens">) => {
  const { org: slug } = await ctx.params;
  const { client, userId } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<Token>(request);
  const id = requireString(b.id, "id", 64);
  const recipient = requireString(b.age_recipient, "age_recipient");
  const scope = requireStrings(b.scope, "scope");
  const createdAt = requireInteger(b.created_at_us, "created_at_us");
  const expires = new Date(requireString(b.expires_at, "expires_at"));
  if (Number.isNaN(expires.getTime())) {
    throw new ApiError(400, "expires_at is not a date");
  }
  const msg = recipientMessage({ kind: "machine", user_id: userId, recipient_id: id, age_recipient: recipient, signing_key: "", scope, created_at_us: createdAt });
  if (!verifySignature(await accountKey(client, userId), msg, b.signature)) {
    throw new ApiError(400, "the token certificate is not signed by your account key");
  }
  await rpc(client, "create_machine_token", {
    p_org: org.id,
    p_id: id,
    p_name: b.name ?? "",
    p_age_recipient: recipient,
    p_scope: scope,
    p_created_at_us: createdAt,
    p_signature: bytea(b.signature, "signature"),
    p_secret_hash: bytea(b.secret_hash, "secret_hash"),
    p_expires_at: expires.toISOString(),
  });
  return Response.json({ id }, { status: 201 });
});
