import { authenticated, body, fromPostgres, handle, requireString, rpc } from "@/lib/api";

// GET: the organizations the caller belongs to, with their role.
// POST: found an organization; the caller's account key becomes its root.

export const GET = handle(async (request) => {
  const { client, userId } = await authenticated(request);
  const { data, error } = await client
    .from("org_members")
    .select("role, scope, organizations(id, slug, name)")
    .eq("user_id", userId)
    .neq("role", "removed");
  if (error) {
    throw fromPostgres(error);
  }
  return Response.json(data.map((m) => ({ ...m.organizations, role: m.role, scope: m.scope })));
});

export const POST = handle(async (request) => {
  const { client } = await authenticated(request);
  const b = await body<{ slug: string; name?: string }>(request);
  const slug = requireString(b.slug, "slug", 40);
  const id = await rpc<string>(client, "create_organization", { p_slug: slug, p_name: b.name || slug });
  return Response.json({ id, slug }, { status: 201 });
});
