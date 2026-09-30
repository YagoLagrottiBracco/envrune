import { authenticated, body, handle, orgBySlug, requireString, rpc } from "@/lib/api";

// POST: create a project in the organization (owners and admins).
export const POST = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/projects">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<{ slug: string; name?: string }>(request);
  const project = requireString(b.slug, "slug", 63);
  const id = await rpc<string>(client, "create_project", { p_org: org.id, p_slug: project, p_name: b.name || project });
  return Response.json({ id, slug: project }, { status: 201 });
});
