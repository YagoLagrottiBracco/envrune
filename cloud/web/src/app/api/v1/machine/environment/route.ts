import { ApiError, base64, fromPostgres, handle, requireString } from "@/lib/api";
import { fromBase64, tokenSecretMatches } from "@/lib/signing";
import { adminClient } from "@/lib/supabase/server";

// GET ?org=&project=&env= with `Authorization: EnvRune-Token <id>.<secret>`:
// what a CI job needs to decrypt one environment. The token's secret is
// checked against its stored hash here; the database then checks the
// token's organization, scope, expiry, and revocation, and logs the fetch.
export const GET = handle(async (request) => {
  const header = request.headers.get("authorization") ?? "";
  const [, id, secret] = header.match(/^EnvRune-Token\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/) ?? [];
  if (!id || !secret) {
    throw new ApiError(401, "send the machine token as `Authorization: EnvRune-Token <id>.<secret>`");
  }
  const admin = adminClient();
  const stored = await admin.rpc("machine_token_secret_hash", { p_id: id });
  if (stored.error) {
    throw fromPostgres(stored.error);
  }
  const hash = stored.data ? fromBase64(base64(stored.data as string)!) : null;
  if (!hash || !tokenSecretMatches(Buffer.from(secret, "base64url"), hash)) {
    throw new ApiError(401, "the machine token is unknown, expired, or revoked");
  }

  const params = new URL(request.url).searchParams;
  const org = requireString(params.get("org"), "org");
  const project = requireString(params.get("project"), "project");
  const env = requireString(params.get("env"), "env");
  const found = await admin
    .from("environments")
    .select("id, projects!inner(slug, organizations!inner(slug))")
    .eq("slug", env)
    .eq("projects.slug", project)
    .eq("projects.organizations.slug", org)
    .maybeSingle();
  if (found.error) {
    throw fromPostgres(found.error);
  }
  if (!found.data) {
    throw new ApiError(404, `no environment ${org}/${project}/${env}`);
  }
  const { data, error } = await admin.rpc("fetch_environment_for_token", { p_token: id, p_env: found.data.id });
  if (error) {
    throw fromPostgres(error);
  }
  return Response.json(data);
});
