import { ApiError, authenticated, body, bytea, handle, requireInteger, requireString, requireStrings, rpc } from "@/lib/api";
import { proxyIdentity } from "@/lib/env";
import { recipientOf } from "@/lib/sensitive";

// POST: write the next version of a sensitive secret, sealed on an owner's
// or admin's device to this server's proxy identity, with the hosts it may
// be sent to. The server stores it without opening it; it opens it only to
// forward a member's request.

interface Sensitive {
  name: string;
  version: number;
  hosts: string[];
  proxy_recipient: string;
  sealed: string;
  device: string;
  signature: string;
}

export const POST = handle(async (request, ctx: RouteContext<"/api/v1/environments/[env]/sensitive">) => {
  const { env } = await ctx.params;
  const { client } = await authenticated(request);
  const identity = proxyIdentity();
  if (!identity) {
    throw new ApiError(404, "this server has no proxy identity, so it does not take sensitive secrets");
  }
  const b = await body<Sensitive>(request);
  // A value sealed to another identity could never be used here.
  if (b.proxy_recipient !== (await recipientOf(identity))) {
    throw new ApiError(409, "the value was sealed for another proxy identity than this server's");
  }
  await rpc(client, "put_sensitive_version", {
    p_env: env,
    p_name: requireString(b.name, "name", 63),
    p_version: requireInteger(b.version, "version"),
    p_hosts: requireStrings(b.hosts, "hosts"),
    p_proxy_recipient: b.proxy_recipient,
    p_sealed: bytea(b.sealed, "sealed"),
    p_device: requireString(b.device, "device", 64),
    p_signature: bytea(b.signature, "signature"),
  });
  return Response.json({ name: b.name, version: b.version }, { status: 201 });
});
