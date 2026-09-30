import { ApiError, authenticated, body, handle, requireInteger, requireString, rpc } from "@/lib/api";

// PUT: store the current epoch's key wrapped for more recipients, such as a
// newly approved device or member. The wrapping device signs each copy;
// clients check that signature, and the database checks that the caller
// administers the environment and that each member may use it.

interface Keys {
  epoch: number;
  device: string;
  keys: { recipient_user_id?: string; recipient_token_id?: string; recipient_id: string; wrapped: string; signature: string }[];
}

export const PUT = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]/keys">) => {
  const { env } = await ctx.params;
  const { client } = await authenticated(request);
  const b = await body<Keys>(request);
  if (!Array.isArray(b.keys) || b.keys.length === 0 || b.keys.length > 500) {
    throw new ApiError(400, "keys must list 1 to 500 wrapped keys");
  }
  await rpc(client, "put_wrapped_keys", {
    p_env: env,
    p_epoch: requireInteger(b.epoch, "epoch"),
    p_device: requireString(b.device, "device", 64),
    p_keys: b.keys,
  });
  return new Response(null, { status: 204 });
});
