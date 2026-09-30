import { authenticated, handle, rpc } from "@/lib/api";

// DELETE: revoke a machine token. Its wrapped keys are deleted and guided
// rotation starts for the environments it fetched.
export const DELETE = handle(async (request, ctx: RouteContext<"/api/v1/tokens/[id]">) => {
  const { id } = await ctx.params;
  const { client } = await authenticated(request);
  await rpc(client, "revoke_machine_token", { p_id: id });
  return new Response(null, { status: 204 });
});
