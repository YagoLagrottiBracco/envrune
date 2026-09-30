import { createClient } from "@supabase/supabase-js";
import { ApiError, body, handle, requireString } from "@/lib/api";
import { publishableKey, supabaseUrl } from "@/lib/env";

// POST { refresh_token }: a new access token for the CLI, so the CLI talks
// only to this API and never to Supabase directly.
export const POST = handle(async (request) => {
  const b = await body<{ refresh_token: string }>(request);
  const client = createClient(supabaseUrl(), publishableKey(), { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await client.auth.refreshSession({ refresh_token: requireString(b.refresh_token, "refresh_token", 4096) });
  if (error || !data.session) {
    throw new ApiError(401, "the session ended; run `envrune login` again");
  }
  const { access_token, refresh_token, expires_at } = data.session;
  return Response.json({ access_token, refresh_token, expires_at });
});
