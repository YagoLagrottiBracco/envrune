import { ApiError, authenticated, body, fromPostgres, handle, orgBySlug, requireString, rpc } from "@/lib/api";

// POST { device }: an owner declares an emergency for a project whose
// secrets must be assumed known. The database revokes the machine tokens
// that reach it, deletes every key wrapped for anyone but the owner's
// device and recovery recipient, and lists every secret for rotation. The
// owner's CLI then starts new keys; this route makes none.
export const POST = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/projects/[project]/emergency">) => {
  const { org: slug, project } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<{ device: string }>(request);
  const { data, error } = await client.from("projects").select("id").eq("org_id", org.id).eq("slug", project).maybeSingle();
  if (error) {
    throw fromPostgres(error);
  }
  if (!data) {
    throw new ApiError(404, `no project ${project} in ${slug}`);
  }
  return Response.json(await rpc(client, "emergency", { p_project: data.id, p_device: requireString(b.device, "device", 64) }));
});
