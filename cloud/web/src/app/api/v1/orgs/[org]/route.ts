import type { SupabaseClient } from "@supabase/supabase-js";
import { ApiError, base64, body, fromPostgres, handle, authenticated, orgBySlug, rpc } from "@/lib/api";
import { certJson, deviceJson, tokenJson } from "@/lib/shapes";

// GET: everything a member's CLI needs to verify and act in an
// organization: the pinned roots, every membership certificate, the
// members' account keys and certified devices, projects, environments,
// secret names and versions, machine tokens (admins only), and open
// rotation tasks, and the sensitive secrets' names and allowed hosts. No
// values and no keys that decrypt them.
//
// PATCH { offline_days }: how many days a device may use its copy of an
// environment without syncing; null turns the limit off.

async function rows<T>(query: PromiseLike<{ data: T[] | null; error: import("@supabase/supabase-js").PostgrestError | null }>): Promise<T[]> {
  const { data, error } = await query;
  if (error) {
    throw fromPostgres(error);
  }
  return data ?? [];
}

export const GET = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  return Response.json(await snapshot(client, org));
});

export const PATCH = handle(async (request, ctx: RouteContext<"/api/v1/orgs/[org]">) => {
  const { org: slug } = await ctx.params;
  const { client } = await authenticated(request);
  const org = await orgBySlug(client, slug);
  const b = await body<{ offline_days: number | null }>(request);
  if (b.offline_days !== null && !Number.isInteger(b.offline_days)) {
    throw new ApiError(400, "offline_days must be a whole number of days, or null");
  }
  await rpc(client, "set_offline_days", { p_org: org.id, p_days: b.offline_days });
  return new Response(null, { status: 204 });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function snapshot(client: SupabaseClient, org: { id: string; slug: string; name: string; offline_days: number | null }): Promise<any> {
  const [roots, certs, members, projects, tokens, tasks, sensitive] = await Promise.all([
    rows(client.from("org_roots").select("user_id, account_key").eq("org_id", org.id)),
    rows(client.from("membership_certs").select("*").eq("org_id", org.id).order("id")),
    rows(client.from("org_members").select("user_id, role, scope").eq("org_id", org.id)),
    rows(client.from("projects").select("id, slug, name, environments(id, slug, epoch, needs_rotation, secrets(id, name, current_version))").eq("org_id", org.id)),
    rows(client.from("machine_tokens").select("*").eq("org_id", org.id)),
    rows(client.from("rotation_tasks").select("id, reason, subject_user_id, subject_token, created_at, rotation_items(secret_id, status)").eq("org_id", org.id)),
    rpc<unknown[]>(client, "sensitive_in_org", { p_org: org.id }),
  ]);
  const memberIds = members.map((m) => m.user_id);
  const [profiles, devices] = await Promise.all([
    rows(client.from("profiles").select("user_id, account_key").in("user_id", memberIds)),
    rows(client.from("devices").select("*").in("user_id", memberIds).not("signature", "is", null).is("revoked_at", null)),
  ]);
  return {
    id: org.id,
    slug: org.slug,
    name: org.name,
    offline_days: org.offline_days,
    roots: roots.map((r) => ({ user_id: r.user_id, account_key: base64(r.account_key) })),
    certificates: certs.map(certJson),
    members,
    accounts: profiles.map((p) => ({ user_id: p.user_id, account_key: base64(p.account_key) })),
    devices: devices.map((d) => deviceJson(d)),
    projects,
    tokens: tokens.map(tokenJson),
    rotation: tasks,
    // Sensitive secrets: where each may be sent and who marked it. Their
    // ciphertext is never sent to a member.
    sensitive,
  };
}
