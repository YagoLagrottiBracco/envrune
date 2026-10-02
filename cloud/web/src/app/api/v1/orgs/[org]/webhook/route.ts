import { ApiError, authenticated, body, bytea, handle, orgBySlug, requireString, rpc } from "@/lib/api";
import { allowedTarget } from "@/lib/webhook";

// The address an organization is told about what happens at.
// GET: the address and how deliveries are going; never the secret.
// PUT { url, secret }: set it. The CLI made the secret and shows it once.
// DELETE: stop sending.

export const GET = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/webhook">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  return Response.json((await rpc(client, "webhook_status", { p_org: org.id })) ?? {});
});

export const PUT = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/webhook">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<{ url: string; secret: string }>(request);
  const url = requireString(b.url, "url", 2000);
  // The same check deliveries make, so a refusal is said now, not later.
  const refused = await allowedTarget(url, process.env["ENVRUNE_WEBHOOK_ALLOW_PRIVATE"] === "1");
  if (refused) {
    throw new ApiError(400, `the webhook cannot be sent to: ${refused}`);
  }
  await rpc(client, "set_webhook", { p_org: org.id, p_url: url, p_secret: bytea(b.secret, "secret") });
  return new Response(null, { status: 204 });
});

export const DELETE = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]/webhook">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  await rpc(client, "clear_webhook", { p_org: org.id });
  return new Response(null, { status: 204 });
});
