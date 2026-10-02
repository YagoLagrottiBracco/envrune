import { ApiError, authenticated, body, handle, requireStrings, rpc } from "@/lib/api";

// POST { decision, base_scope? }: an owner or admin decides a request for
// access, or closes one that ended.
//
//   approve  after their CLI signed the member's membership with the wider
//            scope (POST /orgs/{org}/members); base_scope is the scope
//            before it. Returns until when the access holds.
//   deny     refuses a waiting request.
//   close    after their CLI signed the scope back: lists what the member
//            fetched meanwhile for rotation.
export const POST = handle(async (request, ctx: RouteContext<"/api/v1/access/[id]">) => {
  const { id } = await ctx.params;
  const { client } = await authenticated(request);
  const b = await body<{ decision: string; base_scope?: string[] }>(request);
  switch (b.decision) {
    case "approve":
      return Response.json({ expires_at: await rpc<string>(client, "approve_access", { p_id: id, p_base_scope: requireStrings(b.base_scope, "base_scope") }) });
    case "deny":
      await rpc(client, "deny_access", { p_id: id });
      return new Response(null, { status: 204 });
    case "close":
      await rpc(client, "close_access", { p_id: id });
      return new Response(null, { status: 204 });
  }
  throw new ApiError(400, "decision is approve, deny, or close");
});
