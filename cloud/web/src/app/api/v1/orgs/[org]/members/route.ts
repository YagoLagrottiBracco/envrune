import { accountKey, ApiError, authenticated, body, bytea, fromPostgres, handle, orgBySlug, requireInteger, requireString, requireStrings, rpc } from "@/lib/api";
import { memberMessage, verifySignature } from "@/lib/signing";

// POST: record a membership certificate signed by the caller: add a member,
// change their role or scope, or remove them (role "removed"). Removing a
// member deletes their wrapped keys and opens a rotation task.

interface Membership {
  user_id: string;
  role: string;
  scope: string[];
  issued_at_us: number;
  signature: string;
}

export const POST = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/members">) => {
  const { org: slug } = await ctx.params;
  const { client, userId } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<Membership>(request);
  const member = requireString(b.user_id, "user_id");
  const role = requireString(b.role, "role");
  const scope = requireStrings(b.scope, "scope");
  const issuedAt = requireInteger(b.issued_at_us, "issued_at_us");

  // The certificate covers the member's account key as the server knows it.
  const { data: lookup, error } = await client.rpc("lookup_account_by_id", { p_user: member });
  if (error) {
    throw fromPostgres(error);
  }
  if (!lookup) {
    throw new ApiError(404, "that user has no EnvRune account yet");
  }
  const msg = memberMessage({ org_id: org.id, user_id: member, account_key: lookup, role, scope, issued_at_us: issuedAt, issuer_id: userId });
  if (!verifySignature(await accountKey(client, userId), msg, b.signature)) {
    throw new ApiError(400, "the membership certificate is not signed by your account key");
  }
  await rpc(client, "add_membership", {
    p_org: org.id,
    p_user: member,
    p_role: role,
    p_scope: scope,
    p_issued_at_us: issuedAt,
    p_signature: bytea(b.signature, "signature"),
  });
  return Response.json({ user_id: member, role }, { status: 201 });
});
