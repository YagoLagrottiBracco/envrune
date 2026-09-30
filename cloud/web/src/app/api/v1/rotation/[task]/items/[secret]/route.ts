import { authenticated, body, handle, requireString, rpc } from "@/lib/api";

// PATCH { status }: mark a secret of a guided rotation as rotated (usually
// automatic, when a new version is written) or accepted without rotation.
export const PATCH = handle(async (request, ctx: RouteContext<"/api/v1/rotation/[task]/items/[secret]">) => {
  const { task, secret } = await ctx.params;
  const { client } = await authenticated(request);
  const b = await body<{ status: string }>(request);
  await rpc(client, "update_rotation_item", { p_task: task, p_secret: secret, p_status: requireString(b.status, "status") });
  return new Response(null, { status: 204 });
});
