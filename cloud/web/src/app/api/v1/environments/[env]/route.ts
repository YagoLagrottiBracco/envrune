import { authenticated, handle, requireString, rpc } from "@/lib/api";

// GET ?device=: the caller's wrapped keys for the current epoch, the newest
// version of each secret as ciphertext, and the certificates of the devices
// that wrote or wrapped them. Every fetch is recorded in the audit log.
export const GET = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]">) => {
  const { env } = await ctx.params;
  const { client } = await authenticated(request);
  const device = requireString(new URL(request.url).searchParams.get("device"), "device", 64);
  return Response.json(await rpc(client, "fetch_environment", { p_env: env, p_device: device }));
});
