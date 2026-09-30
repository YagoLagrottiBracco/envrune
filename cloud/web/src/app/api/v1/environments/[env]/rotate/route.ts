import { authenticated, body, handle, requireInteger, requireString, rpc } from "@/lib/api";

// POST: start the next epoch in one transaction: the new key wrapped for the
// remaining recipients, and each secret's current value re-encrypted under
// it. Anyone who lost access keeps only what they could already read.

interface Rotation {
  new_epoch: number;
  device: string;
  keys: unknown[];
  versions: unknown[];
}

export const POST = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]/rotate">) => {
  const { env } = await ctx.params;
  const { client } = await authenticated(request);
  const b = await body<Rotation>(request);
  await rpc(client, "rotate_environment", {
    p_env: env,
    p_new_epoch: requireInteger(b.new_epoch, "new_epoch"),
    p_device: requireString(b.device, "device", 64),
    p_keys: b.keys ?? [],
    p_versions: b.versions ?? [],
  });
  return Response.json({ epoch: b.new_epoch });
});
