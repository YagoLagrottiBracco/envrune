import { authenticated, base64, fromPostgres, handle, orgBySlug } from "@/lib/api";

// GET: the organization's audit log, oldest first, for owners, admins, and
// auditors (row-level security returns nothing to others). Each entry has
// the hash of the previous one, so `envrune cloud audit verify` can detect
// a gap or an edit. ?after=<id> continues from an entry.
export const GET = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/audit">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const after = Number(new URL(request.url).searchParams.get("after") ?? 0);
  const { data, error } = await client
    .from("audit_log")
    .select("*")
    .eq("org_id", org.id)
    .gt("id", Number.isSafeInteger(after) ? after : 0)
    .order("id")
    .limit(1000);
  if (error) {
    throw fromPostgres(error);
  }
  return Response.json(data.map((e) => ({ ...e, prev_hash: base64(e.prev_hash), hash: base64(e.hash) })));
});
