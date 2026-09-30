import { authenticated, handle, rpc } from "@/lib/api";

// DELETE: revoke one of the caller's devices; its environments are marked
// for rotation, since it held their keys.
export const DELETE = handle(async (request, ctx: RouteContext<"/api/v1/devices/[id]">) => {
  const { id } = await ctx.params;
  const { client } = await authenticated(request);
  await rpc(client, "revoke_device", { p_id: id });
  return new Response(null, { status: 204 });
});
