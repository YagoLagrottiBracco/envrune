import { authenticated, handle, rpc } from "@/lib/api";

// GET: when each current value of the environment was written, and when
// each device and token last fetched it, so its owner can tell who already
// has a replaced value. Names and times only. For those who administer the
// environment and for whoever may read the audit log.
export const GET = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]/status">) => {
  const { env } = await ctx.params;
  const { client } = await authenticated(request);
  return Response.json(await rpc(client, "environment_status", { p_env: env }));
});
