import { ApiError, authenticated, body, handle, rpc } from "@/lib/api";

// PUT { until }: until when the value before the current one is still
// expected to work where it was issued, or null to clear it. It is shown to
// people next to who has synced; nothing enforces it.
export const PUT = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]/secrets/[name]/transition">) => {
  const { env, name } = await ctx.params;
  const { client } = await authenticated(request);
  const b = await body<{ until: string | null }>(request);
  if (b.until !== null && (typeof b.until !== "string" || Number.isNaN(Date.parse(b.until)))) {
    throw new ApiError(400, "until must be a time, or null");
  }
  await rpc(client, "set_transition", { p_env: env, p_name: name, p_until: b.until });
  return new Response(null, { status: 204 });
});
