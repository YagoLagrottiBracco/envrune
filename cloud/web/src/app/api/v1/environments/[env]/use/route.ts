import { ApiError, authenticated, body, handle, requireString, rpc } from "@/lib/api";

// POST { device, uses: [{ names, at }] }: commands that injected values
// their user may use but not see, as the device noted them. Recorded in the
// audit log as the device's own account; no value is involved.
export const POST = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]/use">) => {
  const { env } = await ctx.params;
  const { client } = await authenticated(request);
  const b = await body<{ device: string; uses: unknown }>(request);
  if (!Array.isArray(b.uses)) {
    throw new ApiError(400, "uses must be a list");
  }
  await rpc(client, "report_use", { p_env: env, p_device: requireString(b.device, "device", 64), p_uses: b.uses });
  return new Response(null, { status: 204 });
});
