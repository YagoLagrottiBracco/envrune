import { ApiError, authenticated, body, fromPostgres, handle, orgBySlug, requireString, rpc } from "@/lib/api";

// POST: create an environment in a project (owners and admins).
export const POST = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/projects/[project]/environments">) => {
  const { org: slug, project } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const { data, error } = await client.from("projects").select("id").eq("org_id", org.id).eq("slug", project).maybeSingle();
  if (error) {
    throw fromPostgres(error);
  }
  if (!data) {
    throw new ApiError(404, `no project ${project} in ${slug}`);
  }
  const b = await body<{ slug: string }>(request);
  const environment = requireString(b.slug, "slug", 63);
  const id = await rpc<string>(client, "create_environment", { p_project: data.id, p_slug: environment });
  return Response.json({ id, slug: environment }, { status: 201 });
});
