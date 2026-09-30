import { authenticated, body, bytea, handle, requireInteger, requireString, rpc } from "@/lib/api";

// POST: write the next version of a secret, encrypted and signed by the
// writer's device. The database accepts only the next version number and
// the current epoch, so two writers cannot silently overwrite each other.

interface Version {
  name: string;
  version: number;
  epoch: number;
  nonce: string;
  ciphertext: string;
  device: string;
  signature: string;
}

export const POST = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]/secrets">) => {
  const { env } = await ctx.params;
  const { client } = await authenticated(request);
  const b = await body<Version>(request);
  await rpc(client, "put_secret_version", {
    p_env: env,
    p_name: requireString(b.name, "name", 63),
    p_version: requireInteger(b.version, "version"),
    p_epoch: requireInteger(b.epoch, "epoch"),
    p_nonce: bytea(b.nonce, "nonce"),
    p_ciphertext: bytea(b.ciphertext, "ciphertext"),
    p_device: requireString(b.device, "device", 64),
    p_signature: bytea(b.signature, "signature"),
  });
  return Response.json({ name: b.name, version: b.version }, { status: 201 });
});
