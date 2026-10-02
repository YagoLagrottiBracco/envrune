import { authenticated, body, fromPostgres, handle, orgBySlug, requireInteger, requireStrings, rpc } from "@/lib/api";

// Access for a limited time (docs/cloud-operations.md).
// GET: the organization's requests: one's own, or all of them for owners
// and admins. POST { scope, minutes, reason }: ask for environments.

export const GET = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/access">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const { data, error } = await client
    .from("access_grants")
    .select("id, user_id, scope, minutes, reason, status, requested_at, decided_at, expires_at, base_scope, listed_at")
    .eq("org_id", org.id)
    .order("requested_at", { ascending: false })
    .limit(200);
  if (error) {
    throw fromPostgres(error);
  }
  return Response.json(data);
});

export const POST = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/access">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<{ scope: string[]; minutes: number; reason?: string }>(request);
  const id = await rpc<string>(client, "request_access", {
    p_org: org.id,
    p_scope: requireStrings(b.scope, "scope"),
    p_minutes: requireInteger(b.minutes, "minutes"),
    p_reason: typeof b.reason === "string" ? b.reason : "",
  });
  return Response.json({ id }, { status: 201 });
});
