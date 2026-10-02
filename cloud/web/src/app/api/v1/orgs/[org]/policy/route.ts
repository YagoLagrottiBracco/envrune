import { ApiError, authenticated, body, handle, orgBySlug, rpc } from "@/lib/api";

// PUT { rules }: replace the organization's rules about which roles may
// fetch which environments. Owners only; the database checks their shape
// and enforces them wherever ciphertext, keys, or sensitive secrets are
// served. They are listed, for every member, in GET /orgs/{org}.
export const PUT = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/policy">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<{ rules: unknown }>(request);
  if (!Array.isArray(b.rules)) {
    throw new ApiError(400, "rules must be a list");
  }
  await rpc(client, "set_policy", { p_org: org.id, p_rules: b.rules });
  return new Response(null, { status: 204 });
});
